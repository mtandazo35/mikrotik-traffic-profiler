"""Base SQLite de NetFlow: esquema, escritura de un archivo en una transacción, cierre de día, retención y consultas.

Diseño completo en docs/diseno-netflow.md (secciones 3 y 5.3). Las consultas son las que usa el panel:
devuelven tipos simples (serializables con json.dumps) y, con la base vacía o sin datos del filtro, listas
vacías o ceros, nunca una excepción. Solo un periodo, orden o sentido inválido da ValueError.

Convenciones: `ventana`/`hora` en epoch UTC; `dia` = AAAAMMDD en hora de Ecuador (UTC−5 fijo, sin tzdata);
abonados, servidores y redes como enteros IPv4; `router='*'` en las fotos de 7 días = todos los routers.
"""
import calendar
import ipaddress
import os
import re
import shutil
import sqlite3
import time
from collections import defaultdict, namedtuple
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import servicios

RUTA_RELATIVA = "flujos.db"
PERIODOS = ("hoy", "ayer", "7d", "30d")
SENTIDOS = ("saliente", "entrante", "interna")
METRICAS = ("flujos", "tcp_nuevas", "udp", "ips", "puertos", "peers_udp", "syn")
TZ_EC = timezone(timedelta(hours=-5))  # Ecuador no tiene horario de verano
ROTACION = int(os.environ.get("ROTACION_NETFLOW", 60))
FINALES = ("ok", "vacio", "error", "desconocido", "descartado")
PATRON_CRUDO = re.compile(r"^nfcapd\.(\d{12}|\d{14})$")  # 14 cifras si la rotación es de menos de 60 s
CACHE_ASN = "ip2asn-v4.cache"
TOP_DESTINOS_7D = 500
_PODA_DESTINO_BYTES = 50_000_000

_DDL = """
CREATE TABLE IF NOT EXISTS meta (clave TEXT PRIMARY KEY, valor TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS archivos (
  ruta TEXT PRIMARY KEY,
  exportador TEXT NOT NULL,
  router TEXT,
  ventana INTEGER NOT NULL,
  tam INTEGER NOT NULL, mtime INTEGER NOT NULL,
  estado TEXT NOT NULL CHECK (estado IN ('ok','vacio','reintentar','error','desconocido','descartado')),
  intentos INTEGER NOT NULL DEFAULT 0,
  flujos_total INTEGER, bytes_total INTEGER, secuencia_perdida INTEGER,
  flujos_categoria INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  omitidos INTEGER,
  segundos REAL, procesado INTEGER, borrado INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS archivos_ventana ON archivos(ventana);
CREATE INDEX IF NOT EXISTS archivos_router ON archivos(router, ventana);

CREATE TABLE IF NOT EXISTS exportador_desconocido (
  ip TEXT PRIMARY KEY, primero INTEGER, ultimo INTEGER, archivos INTEGER, flujos INTEGER);

CREATE TABLE IF NOT EXISTS asn (asn INTEGER PRIMARY KEY, nombre TEXT NOT NULL, pais TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS dia_cierre (dia INTEGER PRIMARY KEY, cerrado INTEGER, sucio INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS total_hora (
  hora INTEGER, router TEXT, categoria TEXT,
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  abonados_max_ventana INTEGER, ventanas INTEGER,
  PRIMARY KEY (hora, router, categoria)) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS interfaz_dia (
  dia INTEGER, router TEXT, entrada INTEGER, salida INTEGER, flujos INTEGER, bytes INTEGER,
  PRIMARY KEY (dia, router, entrada, salida)) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS uso_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER, abonado INTEGER,
  flujos INTEGER, bytes INTEGER,
  PRIMARY KEY (dia, router, categoria, sentido, proto, puerto, abonado)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS destino_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, asn INTEGER, abonado INTEGER,
  flujos INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  PRIMARY KEY (dia, router, categoria, asn, abonado)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dns_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, proto INTEGER, puerto INTEGER, servidor INTEGER, abonado INTEGER,
  flujos INTEGER,
  PRIMARY KEY (dia, router, categoria, proto, puerto, servidor, abonado)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS no_publico_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, red INTEGER, abonado INTEGER, flujos INTEGER, bytes INTEGER,
  PRIMARY KEY (dia, router, categoria, red, abonado)) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS servicio_dia (
  dia INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER,
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  abonados_max_ventana INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, sentido, proto, puerto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS puerto_dia (
  dia INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER,
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER, abonados_max_ventana INTEGER,
  PRIMARY KEY (dia, router, categoria, sentido, proto, puerto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS destino_dia (
  dia INTEGER, router TEXT, categoria TEXT, asn INTEGER,
  flujos INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, asn)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dns_dia (
  dia INTEGER, router TEXT, categoria TEXT, proto INTEGER, puerto INTEGER, servidor INTEGER,
  flujos INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, proto, puerto, servidor)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS no_publico_dia (
  dia INTEGER, router TEXT, categoria TEXT, red INTEGER, flujos INTEGER, bytes INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, red)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, abonado INTEGER,
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER, ventanas INTEGER,
  max_flujos INTEGER, max_tcp_nuevas INTEGER, max_udp INTEGER, max_ips INTEGER, max_puertos INTEGER,
  max_peers_udp INTEGER, max_syn INTEGER,
  PRIMARY KEY (dia, router, categoria, abonado)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hist_dia (
  dia INTEGER, router TEXT, categoria TEXT, metrica TEXT, cubo INTEGER, n INTEGER,
  PRIMARY KEY (dia, router, categoria, metrica, cubo)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS senal_dia (
  dia INTEGER, router TEXT, categoria TEXT,
  tipo TEXT CHECK (tipo IN ('sensible','reflector','barrido','p2p')),
  detalle TEXT,
  abonado INTEGER, flujos INTEGER, remotos_max_ventana INTEGER, ventanas INTEGER, ultima INTEGER,
  PRIMARY KEY (dia, router, categoria, tipo, detalle, abonado)) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS servicio_7d (
  hasta INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER,
  abonados INTEGER, flujos INTEGER, bytes INTEGER, dias_observado INTEGER,
  PRIMARY KEY (hasta, router, categoria, sentido, proto, puerto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS destino_7d (
  hasta INTEGER, router TEXT, categoria TEXT, asn INTEGER,
  abonados INTEGER, flujos INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  PRIMARY KEY (hasta, router, categoria, asn)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS activos_7d (
  hasta INTEGER, router TEXT, categoria TEXT, abonados INTEGER, dias_con_datos INTEGER,
  PRIMARY KEY (hasta, router, categoria)) WITHOUT ROWID;
"""

# Tablas que se escriben por archivo: (columnas de la clave, columnas que se suman, columnas con máximo).
# El orden de las columnas es el de las filas que arma flujos.Agregador.filas().
TABLAS_ARCHIVO = {
    "total_hora": (("hora", "router", "categoria"),
                   ("flujos", "paquetes", "bytes_subida", "bytes_bajada", "ventanas"), ("abonados_max_ventana",)),
    "interfaz_dia": (("dia", "router", "entrada", "salida"), ("flujos", "bytes"), ()),
    "uso_abonado_dia": (("dia", "router", "categoria", "sentido", "proto", "puerto", "abonado"), ("flujos", "bytes"), ()),
    "destino_abonado_dia": (("dia", "router", "categoria", "asn", "abonado"),
                            ("flujos", "bytes_subida", "bytes_bajada"), ()),
    "dns_abonado_dia": (("dia", "router", "categoria", "proto", "puerto", "servidor", "abonado"), ("flujos",), ()),
    "no_publico_abonado_dia": (("dia", "router", "categoria", "red", "abonado"), ("flujos", "bytes"), ()),
    "servicio_dia": (("dia", "router", "categoria", "sentido", "proto", "puerto"),
                     ("flujos", "paquetes", "bytes_subida", "bytes_bajada"), ("abonados_max_ventana",)),
    "puerto_dia": (("dia", "router", "categoria", "sentido", "proto", "puerto"),
                   ("flujos", "paquetes", "bytes_subida", "bytes_bajada"), ("abonados_max_ventana",)),
    "destino_dia": (("dia", "router", "categoria", "asn"), ("flujos", "bytes_subida", "bytes_bajada"), ()),
    "dns_dia": (("dia", "router", "categoria", "proto", "puerto", "servidor"), ("flujos",), ()),
    "no_publico_dia": (("dia", "router", "categoria", "red"), ("flujos", "bytes"), ()),
    "abonado_dia": (("dia", "router", "categoria", "abonado"),
                    ("flujos", "paquetes", "bytes_subida", "bytes_bajada", "ventanas"),
                    ("max_flujos", "max_tcp_nuevas", "max_udp", "max_ips", "max_puertos", "max_peers_udp", "max_syn")),
    "hist_dia": (("dia", "router", "categoria", "metrica", "cubo"), ("n",), ()),
    "senal_dia": (("dia", "router", "categoria", "tipo", "detalle", "abonado"), ("flujos", "ventanas"),
                  ("remotos_max_ventana", "ultima")),
}

# Retención (sección 3.6): tabla -> (columna, días). Se borra lo anterior a hoy − N días.
RETENCION = {
    "archivos": ("ventana", 35),
    "exportador_desconocido": ("ultimo", 35),
    "uso_abonado_dia": ("dia", 14),
    "destino_abonado_dia": ("dia", 8),
    "dns_abonado_dia": ("dia", 14),
    "no_publico_abonado_dia": ("dia", 14),
    "abonado_dia": ("dia", 90),
    "puerto_dia": ("dia", 90),
    "interfaz_dia": ("dia", 90),
    "senal_dia": ("dia", 90),
    "servicio_7d": ("hasta", 90),
    "destino_7d": ("hasta", 90),
    "destino_dia": ("dia", 180),
    "servicio_dia": ("dia", 400),
    "hist_dia": ("dia", 400),
    "dns_dia": ("dia", 400),
    "no_publico_dia": ("dia", 400),
    "activos_7d": ("hasta", 400),
    "total_hora": ("hora", 400),
    "dia_cierre": ("dia", 400),
}

_COLS_ARCHIVO = ("ruta", "exportador", "router", "ventana", "tam", "mtime", "estado", "intentos", "flujos_total",
                 "bytes_total", "secuencia_perdida", "flujos_categoria", "bytes_subida", "bytes_bajada", "omitidos",
                 "segundos", "procesado", "borrado", "error")
_ASN_FIJOS = {0: ("sin ASN / no público", ""), -1: ("otros (agrupados)", "")}

Crudo = namedtuple("Crudo", "ruta exportador ventana camino tam mtime")


def _sql_upsert(tabla, clave, sumas, maximos):
    cols = clave + sumas + maximos
    cambios = [f"{c} = {c} + excluded.{c}" for c in sumas] + [f"{c} = max({c}, excluded.{c})" for c in maximos]
    return (f"INSERT INTO {tabla} ({', '.join(cols)}) VALUES ({', '.join('?' * len(cols))}) "
            f"ON CONFLICT ({', '.join(clave)}) DO UPDATE SET {', '.join(cambios)}")


_UPSERT = {t: _sql_upsert(t, *d) for t, d in TABLAS_ARCHIVO.items()}


def _ahora():
    """Reloj de las consultas (las pruebas lo sustituyen)."""
    return time.time()


# ---------- fechas ----------

def dia_de(epoch):
    d = datetime.fromtimestamp(epoch, TZ_EC)
    return d.year * 10000 + d.month * 100 + d.day


def _fecha(dia):
    return date(dia // 10000, dia // 100 % 100, dia % 100)


def sumar_dias(dia, n):
    d = _fecha(dia) + timedelta(days=n)
    return d.year * 10000 + d.month * 100 + d.day


def inicio_dia(dia):
    f = _fecha(dia)
    return int(datetime(f.year, f.month, f.day, tzinfo=TZ_EC).timestamp())


def dia_iso(dia):
    return _fecha(dia).isoformat()


def iso(epoch):
    return datetime.fromtimestamp(epoch, TZ_EC).isoformat(timespec="seconds")


def dia_desde_iso(texto):
    f = date.fromisoformat(texto)
    return f.year * 10000 + f.month * 100 + f.day


# ---------- histogramas ----------

def cubo(v):
    """v si v < 100; si no, dos cifras significativas truncadas (1234 -> 1200)."""
    if v < 100:
        return v
    m = 10 ** (len(str(v)) - 2)
    return v - v % m


def cota(c):
    """Cota superior de un cubo (lo que se informa como percentil: error ≤ 10 %, siempre hacia arriba)."""
    if c < 100:
        return c
    return c + 10 ** (len(str(c)) - 2) - 1


# ---------- conexión y esquema ----------

def abrir(ruta, solo_lectura=False):
    """Conexión en modo autocommit (las transacciones se abren a mano). solo_lectura: la base debe existir."""
    ruta = Path(ruta)
    if solo_lectura:
        if not ruta.is_file():
            raise FileNotFoundError(str(ruta))
        con = sqlite3.connect(ruta.resolve().as_uri() + "?mode=ro", uri=True, timeout=5, isolation_level=None)
        con.execute("PRAGMA busy_timeout = 5000")
        return con
    con = sqlite3.connect(str(ruta), timeout=30, isolation_level=None)
    con.execute("PRAGMA busy_timeout = 30000")
    con.execute("PRAGMA cache_size = -65536")  # 64 MB
    return con


def crear_esquema(con):
    """Idempotente. auto_vacuum solo surte efecto antes de crear la primera tabla."""
    con.execute("PRAGMA auto_vacuum = INCREMENTAL")
    con.execute("PRAGMA journal_mode = WAL")
    con.execute("PRAGMA synchronous = NORMAL")
    con.executescript(_DDL)
    con.execute("INSERT OR IGNORE INTO meta VALUES ('version_esquema', '1')")


def _hay_esquema(con):
    try:
        return con.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'archivos'").fetchone() is not None
    except sqlite3.Error:
        return False


def datos_de(con):
    """Carpeta de datos de una conexión (la de la base)."""
    for _, nombre, archivo in con.execute("PRAGMA database_list"):
        if nombre == "main" and archivo:
            return Path(archivo).parent
    return None


def leer_meta(con, clave):
    f = con.execute("SELECT valor FROM meta WHERE clave = ?", (clave,)).fetchone()
    return f[0] if f else None


def poner_meta(con, clave, valor):
    con.execute("INSERT INTO meta VALUES (?, ?) ON CONFLICT(clave) DO UPDATE SET valor = excluded.valor",
                (clave, str(valor)))


# ---------- escritura ----------

def _fila_archivo(con, fila):
    valores = [fila.get(c) for c in _COLS_ARCHIVO]
    valores[_COLS_ARCHIVO.index("intentos")] = fila.get("intentos") or 0
    cambios = ", ".join(f"{c} = excluded.{c}" for c in _COLS_ARCHIVO[1:])
    con.execute(f"INSERT INTO archivos ({', '.join(_COLS_ARCHIVO)}) VALUES ({', '.join('?' * len(_COLS_ARCHIVO))}) "
                f"ON CONFLICT(ruta) DO UPDATE SET {cambios}", valores)


def guardar_archivo(con, fila, filas):
    """Todos los contadores de un archivo y su fila de checkpoint en UNA transacción: o todo o nada."""
    con.execute("BEGIN IMMEDIATE")
    try:
        for tabla, valores in filas.items():
            if valores:
                con.executemany(_UPSERT[tabla], valores)
        _fila_archivo(con, fila)
        if filas:
            # archivo tardío de un día ya cerrado: hay que recalcular sus abonados
            con.execute("UPDATE dia_cierre SET sucio = 1 WHERE dia = ? AND cerrado IS NOT NULL",
                        (dia_de(fila["ventana"]),))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


def registrar_desconocido(con, fila):
    """Exportador sin router en el inventario: se anota (no se procesa) para que el panel lo muestre."""
    con.execute("BEGIN IMMEDIATE")
    try:
        con.execute("INSERT INTO exportador_desconocido VALUES (?, ?, ?, 1, ?) ON CONFLICT(ip) DO UPDATE SET "
                    "primero = min(primero, excluded.primero), ultimo = max(ultimo, excluded.ultimo), "
                    "archivos = archivos + 1, flujos = flujos + excluded.flujos",
                    (fila["exportador"], fila["ventana"], fila["ventana"], fila.get("flujos_total") or 0))
        _fila_archivo(con, fila)
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


def registrar_fallo(con, fila):
    """Solo la fila de checkpoint (estado reintentar/error): ningún contador."""
    _fila_archivo(con, fila)


def marcar_cambiado(con, ruta, texto):
    con.execute("UPDATE archivos SET error = ? WHERE ruta = ?", (texto, ruta))


def marcar_borrados(con, rutas, ahora):
    con.executemany("UPDATE archivos SET borrado = ? WHERE ruta = ?", [(int(ahora), r) for r in rutas])


def descartar(con, crudos, ahora):
    """Crudo sin procesar borrado por disco lleno: queda registrado como 'descartado'."""
    for c in crudos:
        _fila_archivo(con, {"ruta": c.ruta, "exportador": c.exportador, "router": None, "ventana": c.ventana,
                            "tam": c.tam, "mtime": c.mtime, "estado": "descartado", "error": "disco lleno",
                            "borrado": int(ahora)})


def estados(con):
    """{ruta: {...}} de los archivos que siguen en disco (borrado NULL)."""
    return {f[0]: {"estado": f[1], "tam": f[2], "mtime": f[3], "intentos": f[4], "error": f[5]}
            for f in con.execute("SELECT ruta, estado, tam, mtime, intentos, error FROM archivos WHERE borrado IS NULL")}


def actualizar_asn(con, nombres, mtime):
    """Reemplaza la tabla de nombres de ASN (cuando cambia el TSV de iptoasn)."""
    con.execute("BEGIN IMMEDIATE")
    try:
        con.execute("DELETE FROM asn")
        con.executemany("INSERT OR REPLACE INTO asn VALUES (?, ?, ?)", nombres)
        con.executemany("INSERT OR REPLACE INTO asn VALUES (?, ?, ?)",
                        [(a, n, p) for a, (n, p) in _ASN_FIJOS.items()])
        poner_meta(con, "asn_mtime", mtime)
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


# ---------- crudo en disco ----------

def ip_de_carpeta(nombre):
    """'192-0-2-1' -> '192.0.2.1' (así nombra nfcapd -M los subdirectorios), o None."""
    try:
        return str(ipaddress.IPv4Address(nombre.replace("-", ".")))
    except ValueError:
        return None


def ventana_de(sello):
    formato = "%Y%m%d%H%M%S" if len(sello) == 14 else "%Y%m%d%H%M"
    return calendar.timegm(time.strptime(sello, formato))  # el colector corre con TZ=UTC


def listar_crudo(datos):
    """Archivos cerrados de data/nfcapd/<exportador>/nfcapd.AAAAmmddHHMM, de la ventana más vieja a la más nueva."""
    base = Path(datos) / "nfcapd"
    salida = []
    if not base.is_dir():
        return salida
    for carpeta in base.iterdir():
        ip = ip_de_carpeta(carpeta.name) if carpeta.is_dir() else None
        if not ip:
            continue
        for f in carpeta.iterdir():
            m = PATRON_CRUDO.match(f.name)
            if not m:
                continue  # nfcapd.current.<pid>, .nfstat y lo demás
            try:
                st = f.stat()
                ventana = ventana_de(m.group(1))
            except (OSError, ValueError):
                continue
            salida.append(Crudo(f"{carpeta.name}/{f.name}", ip, ventana, f, st.st_size, int(st.st_mtime)))
    salida.sort(key=lambda c: (c.ventana, c.ruta))
    return salida


def listo(c, ahora, rotacion=None):
    """Cerrado de verdad: pasaron dos rotaciones (nfcapd puede añadir una vez tras reiniciar) y no se toca hace 30 s."""
    rot = ROTACION if rotacion is None else rotacion
    return ahora >= c.ventana + 2 * rot + 30 and c.mtime <= ahora - 30


def pendientes(con, datos, ahora, exportadores=None):
    """Archivos listos que todavía no tienen estado final."""
    if datos is None:
        return 0
    est = estados(con) if _hay_esquema(con) else {}
    n = 0
    for c in listar_crudo(datos):
        if exportadores is not None and c.exportador not in exportadores:
            continue
        e = est.get(c.ruta)
        if (not e or e["estado"] not in FINALES) and listo(c, ahora):
            n += 1
    return n


def peso(carpeta):
    total = 0
    for raiz, _, archivos in os.walk(carpeta):
        for a in archivos:
            try:
                total += os.stat(os.path.join(raiz, a)).st_size
            except OSError:
                pass
    return total


def limites_disco(extra=None):
    """Umbrales del guardián (variables de mtp.env) más los que se pasen."""
    def num(nombre, defecto):
        try:
            return float(os.environ.get(nombre, defecto))
        except ValueError:
            return float(defecto)
    lim = {"crudo_horas": num("CRUDO_HORAS", 6), "crudo_max_gb": num("CRUDO_MAX_GB", 6),
           "min_libre_pct": num("DISCO_MIN_LIBRE_PCT", 15), "critico_pct": num("DISCO_CRITICO_PCT", 8)}
    lim.update(extra or {})
    return lim


def libre_pct(datos, uso=shutil.disk_usage):
    u = _uso(datos, uso)
    return 100.0 * u.free / u.total if u and u.total else 100.0


def _uso(datos, uso):
    carpeta = Path(datos)
    while not carpeta.exists() and carpeta.parent != carpeta:
        carpeta = carpeta.parent
    try:
        return uso(str(carpeta))
    except OSError:
        return None


def nivel_disco(pct, lim):
    if pct < lim["critico_pct"]:
        return "critico"
    if pct < lim["min_libre_pct"]:
        return "aviso"
    return "ok"


def estado_disco(datos, uso=shutil.disk_usage, limites=None):
    datos = Path(datos)
    u = _uso(datos, uso)
    total, libre = (u.total, u.free) if u else (0, 0)
    pct = round(100.0 * libre / total, 1) if total else 0.0
    db = 0
    for sufijo in ("", "-wal", "-shm"):
        try:
            db += (datos / (RUTA_RELATIVA + sufijo)).stat().st_size
        except OSError:
            pass
    return {"total_bytes": total, "libre_bytes": libre, "libre_pct": pct,
            "crudo_bytes": peso(datos / "nfcapd"), "db_bytes": db,
            "estado": nivel_disco(pct, limites_disco(limites)) if total else "ok"}


# ---------- cierre del día ----------

def _recontar(con, d):
    for tabla, presencia, cols in (("servicio_dia", "uso_abonado_dia", ("sentido", "proto", "puerto")),
                                   ("destino_dia", "destino_abonado_dia", ("asn",)),
                                   ("dns_dia", "dns_abonado_dia", ("proto", "puerto", "servidor")),
                                   ("no_publico_dia", "no_publico_abonado_dia", ("red",))):
        igual = " AND ".join(f"p.{c} = {tabla}.{c}" for c in ("dia", "router", "categoria") + cols)
        con.execute(f"UPDATE {tabla} SET abonados = (SELECT COUNT(*) FROM {presencia} p WHERE {igual}) WHERE dia = ?",
                    (d,))


def _podar_puertos(con, d):
    """Puertos sin catálogo poco vistos se suman en su cubo (-1/-2) y se borran."""
    cubos = defaultdict(lambda: [0, 0, 0, 0, 0])
    borrar = []
    for router, cat, s, proto, puerto, fl, pk, sub, baj, mx in con.execute(
            "SELECT router, categoria, sentido, proto, puerto, flujos, paquetes, bytes_subida, bytes_bajada, "
            "abonados_max_ventana FROM puerto_dia WHERE dia = ? AND puerto >= 1024 AND abonados_max_ventana < 2 "
            "AND flujos < 100", (d,)).fetchall():
        k = servicios.clave(servicios.proto_nombre(proto), puerto)
        if k >= 0:
            continue  # del catálogo o de un rango con nombre
        c = cubos[(router, cat, s, proto, k)]
        c[0] += fl
        c[1] += pk
        c[2] += sub
        c[3] += baj
        c[4] = max(c[4], mx)
        borrar.append((d, router, cat, s, proto, puerto))
    con.executemany("DELETE FROM puerto_dia WHERE dia = ? AND router = ? AND categoria = ? AND sentido = ? "
                    "AND proto = ? AND puerto = ?", borrar)
    con.executemany(_UPSERT["puerto_dia"], [(d, *k, *v) for k, v in cubos.items()])


def _podar_destinos(con, d):
    """ASN con menos de 2 abonados y menos de 50 MB en el día se juntan en asn = -1."""
    otros = defaultdict(lambda: [0, 0, 0])
    borrar = []
    for router, cat, asn, fl, sub, baj in con.execute(
            "SELECT router, categoria, asn, flujos, bytes_subida, bytes_bajada FROM destino_dia WHERE dia = ? "
            "AND asn > 0 AND COALESCE(abonados, 0) < 2 AND bytes_subida + bytes_bajada < ?",
            (d, _PODA_DESTINO_BYTES)).fetchall():
        o = otros[(router, cat)]
        o[0] += fl
        o[1] += sub
        o[2] += baj
        borrar.append((d, router, cat, asn))
    con.executemany("DELETE FROM destino_dia WHERE dia = ? AND router = ? AND categoria = ? AND asn = ?", borrar)
    con.executemany(_UPSERT["destino_dia"], [(d, r, c, -1, *v) for (r, c), v in otros.items()])
    # abonados del grupo -1: los que fueron a algún ASN que ya no tiene fila propia
    con.execute("UPDATE destino_dia SET abonados = (SELECT COUNT(DISTINCT p.abonado) FROM destino_abonado_dia p "
                "WHERE p.dia = destino_dia.dia AND p.router = destino_dia.router AND p.categoria = destino_dia.categoria "
                "AND NOT EXISTS (SELECT 1 FROM destino_dia x WHERE x.dia = p.dia AND x.router = p.router "
                "AND x.categoria = p.categoria AND x.asn = p.asn)) WHERE dia = ? AND asn = -1", (d,))


def _fotos(con, d):
    """Fotos exactas de 7 días (D−6..D) por router y para todos ('*')."""
    rango = (sumar_dias(d, -6), d)
    for t in ("servicio_7d", "destino_7d", "activos_7d"):
        con.execute(f"DELETE FROM {t} WHERE hasta = ?", (d,))

    filas = [(d, r, c, a, n) for r, c, a, n in con.execute(
        "SELECT router, categoria, COUNT(DISTINCT abonado), COUNT(DISTINCT dia) FROM abonado_dia "
        "WHERE dia BETWEEN ? AND ? GROUP BY router, categoria", rango)]
    filas += [(d, "*", c, a, n) for c, a, n in con.execute(
        "SELECT categoria, COUNT(DISTINCT router || '/' || abonado), COUNT(DISTINCT dia) FROM abonado_dia "
        "WHERE dia BETWEEN ? AND ? GROUP BY categoria", rango)]
    con.executemany("INSERT INTO activos_7d VALUES (?, ?, ?, ?, ?)", filas)

    abonados = {}
    for r, c, s, p, pu, n in con.execute(
            "SELECT router, categoria, sentido, proto, puerto, COUNT(DISTINCT abonado) FROM uso_abonado_dia "
            "WHERE dia BETWEEN ? AND ? GROUP BY router, categoria, sentido, proto, puerto", rango):
        abonados[(r, c, s, p, pu)] = n
    for c, s, p, pu, n in con.execute(
            "SELECT categoria, sentido, proto, puerto, COUNT(DISTINCT router || '/' || abonado) FROM uso_abonado_dia "
            "WHERE dia BETWEEN ? AND ? GROUP BY categoria, sentido, proto, puerto", rango):
        abonados[("*", c, s, p, pu)] = n
    acum = defaultdict(lambda: [0, 0, set()])
    for r, c, s, p, pu, dia, fl, by in con.execute(
            "SELECT router, categoria, sentido, proto, puerto, dia, flujos, bytes_subida + bytes_bajada "
            "FROM servicio_dia WHERE dia BETWEEN ? AND ?", rango):
        for rr in (r, "*"):
            a = acum[(rr, c, s, p, pu)]
            a[0] += fl
            a[1] += by
            a[2].add(dia)
    con.executemany("INSERT INTO servicio_7d VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [(d, *k, abonados.get(k, 0), v[0], v[1], len(v[2])) for k, v in acum.items()])

    grupos = defaultdict(list)
    for r, c, asn, a, fl, sub, baj in con.execute(
            "SELECT router, categoria, asn, COUNT(DISTINCT abonado), SUM(flujos), SUM(bytes_subida), "
            "SUM(bytes_bajada) FROM destino_abonado_dia WHERE dia BETWEEN ? AND ? GROUP BY router, categoria, asn",
            rango):
        grupos[(r, c)].append((asn, a, fl, sub, baj))
    for c, asn, a, fl, sub, baj in con.execute(
            "SELECT categoria, asn, COUNT(DISTINCT router || '/' || abonado), SUM(flujos), SUM(bytes_subida), "
            "SUM(bytes_bajada) FROM destino_abonado_dia WHERE dia BETWEEN ? AND ? GROUP BY categoria, asn", rango):
        grupos[("*", c)].append((asn, a, fl, sub, baj))
    filas = []
    for (r, c), lista in grupos.items():
        # los 500 primeros por abonados y los 500 primeros por bytes (sirve a los dos órdenes del panel)
        quedan = {f[0]: f for f in sorted(lista, key=lambda f: -f[1])[:TOP_DESTINOS_7D]}
        quedan.update({f[0]: f for f in sorted(lista, key=lambda f: -(f[3] + f[4]))[:TOP_DESTINOS_7D]})
        filas += [(d, r, c, *f) for f in quedan.values()]
    con.executemany("INSERT INTO destino_7d VALUES (?, ?, ?, ?, ?, ?, ?, ?)", filas)


def cerrar_dia(con, d, ahora):
    """Abonados exactos, poda y fotos de 7 días del día d. Repetible mientras la presencia de d siga guardada."""
    con.execute("BEGIN IMMEDIATE")
    try:
        if con.execute("SELECT 1 FROM uso_abonado_dia WHERE dia = ? LIMIT 1", (d,)).fetchone():
            _recontar(con, d)
            _podar_puertos(con, d)
            _podar_destinos(con, d)
            _fotos(con, d)
        con.execute("INSERT INTO dia_cierre (dia, cerrado, sucio) VALUES (?, ?, 0) "
                    "ON CONFLICT(dia) DO UPDATE SET cerrado = excluded.cerrado, sucio = 0", (d, int(ahora)))
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise


def cerrar_dias(con, ahora):
    """Cierra los días terminados hace más de 2 h y los sucios (llegó un archivo después del cierre)."""
    dias = {dia_de(h) for (h,) in con.execute("SELECT DISTINCT hora FROM total_hora WHERE hora >= ?",
                                               (int(ahora) - 15 * 86400,))}
    cierre = {d: (c, s) for d, c, s in con.execute("SELECT dia, cerrado, sucio FROM dia_cierre")}
    dias |= {d for d, (_, s) in cierre.items() if s}
    hechos, recerrados = [], []
    for d in sorted(dias):
        cerrado, sucio = cierre.get(d, (None, 0))
        if cerrado is not None and not sucio:
            continue
        if ahora < inicio_dia(d) + 86400 + 7200:
            continue
        cerrar_dia(con, d, ahora)
        hechos.append(d)
        if cerrado is not None:
            recerrados.append(d)
    # las fotos de 7 días posteriores que incluyen un día recalculado también cambian
    rehacer = {sumar_dias(d, k) for d in recerrados for k in range(1, 7)}
    for d in sorted(rehacer - set(hechos)):
        if cierre.get(d, (None, 0))[0] is not None:
            con.execute("BEGIN IMMEDIATE")
            try:
                _fotos(con, d)
                con.execute("COMMIT")
            except BaseException:
                con.execute("ROLLBACK")
                raise
    return hechos


def retencion(con, ahora):
    """Borra lo que pasó su retención (RETENCION) y devuelve las filas borradas por tabla."""
    hoy = dia_de(ahora)
    borradas = {}
    con.execute("BEGIN IMMEDIATE")
    try:
        for tabla, (col, n) in RETENCION.items():
            limite = sumar_dias(hoy, -n) if col in ("dia", "hasta") else int(ahora) - n * 86400
            borradas[tabla] = con.execute(f"DELETE FROM {tabla} WHERE {col} < ?", (limite,)).rowcount
        poner_meta(con, "ultima_retencion", hoy)
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise
    con.execute("PRAGMA incremental_vacuum(5000)").fetchall()
    return borradas


# ---------- consultas (contrato 5.3) ----------

def _validar(valor, opciones, que):
    if valor not in opciones:
        raise ValueError(f"{que} inválido: {valor!r} (uno de {', '.join(opciones)})")


def _dias(periodo):
    _validar(periodo, PERIODOS, "periodo")
    hoy = dia_de(_ahora())
    if periodo == "hoy":
        return [hoy]
    ayer = sumar_dias(hoy, -1)
    n = {"ayer": 1, "7d": 7, "30d": 30}[periodo]
    return [sumar_dias(ayer, -i) for i in range(n - 1, -1, -1)]


def _modo(periodo):
    return "max_diario" if periodo == "30d" else "exacto"


def _cond(categoria, router, desde, hasta, col="dia", **iguales):
    texto = f"categoria = ? AND {col} BETWEEN ? AND ?"
    params = [categoria, desde, hasta]
    if router:
        texto += " AND router = ?"
        params.append(router)
    for c, v in iguales.items():
        texto += f" AND {c} = ?"
        params.append(v)
    return texto, params


def _pct(n, total):
    return round(100.0 * n / total, 1) if total else 0.0


def _ip(n):
    return str(ipaddress.IPv4Address(n))


def _presencia(con, tabla, cols, categoria, router, dias, **iguales):
    """{clave: abonados distintos (router, abonado)} exactos en los días, desde una tabla de presencia."""
    cond, params = _cond(categoria, router, dias[0], dias[-1], **iguales)
    sel = ", ".join(cols)
    if len(dias) == 1:  # la clave primaria ya hace única cada pareja (router, abonado) del día
        sql = f"SELECT {sel}, COUNT(*) FROM {tabla} WHERE {cond} GROUP BY {sel}"
    else:
        sql = (f"SELECT {sel}, COUNT(*) FROM (SELECT DISTINCT {sel}, router, abonado FROM {tabla} "
               f"WHERE {cond}) GROUP BY {sel}")
    return {tuple(f[:-1]): f[-1] for f in con.execute(sql, params)}


def _max_diario(con, tabla, cols, categoria, router, dias, **iguales):
    """{clave: máximo diario de abonados} desde la columna `abonados` (rellenada al cerrar cada día)."""
    cond, params = _cond(categoria, router, dias[0], dias[-1], **iguales)
    sel = ", ".join(cols)
    salida = {}
    for f in con.execute(f"SELECT dia, {sel}, SUM(COALESCE(abonados, 0)) FROM {tabla} WHERE {cond} "
                         f"GROUP BY dia, {sel}", params):
        k = tuple(f[1:-1])
        salida[k] = max(salida.get(k, 0), f[-1])
    return salida


def _abonados_por(con, presencia, tabla_dia, cols, categoria, router, dias, modo, **iguales):
    if modo == "max_diario":
        return _max_diario(con, tabla_dia, cols, categoria, router, dias, **iguales)
    return _presencia(con, presencia, cols, categoria, router, dias, **iguales)


def _activos(con, categoria, router, dias, modo):
    cond, params = _cond(categoria, router, dias[0], dias[-1])
    if modo == "max_diario":
        sql = f"SELECT MAX(n) FROM (SELECT COUNT(*) AS n FROM abonado_dia WHERE {cond} GROUP BY dia)"
    elif len(dias) == 1:
        sql = f"SELECT COUNT(*) FROM abonado_dia WHERE {cond}"
    else:
        sql = f"SELECT COUNT(*) FROM (SELECT DISTINCT router, abonado FROM abonado_dia WHERE {cond})"
    return con.execute(sql, params).fetchone()[0] or 0


def _totales(con, categoria, router, dias):
    """routers, días con datos y sumas de total_hora en los días."""
    cond, params = _cond(categoria, router, inicio_dia(dias[0]), inicio_dia(dias[-1]) + 86399, col="hora")
    routers, con_datos, sumas = set(), set(), [0, 0, 0]
    for r, h, fl, sub, baj in con.execute(
            f"SELECT router, hora, flujos, bytes_subida, bytes_bajada FROM total_hora WHERE {cond}", params):
        routers.add(r)
        con_datos.add(dia_de(h))
        sumas[0] += fl or 0
        sumas[1] += sub or 0
        sumas[2] += baj or 0
    return sorted(routers), len(con_datos), sumas


def _hay_foto(con, categoria, router, hasta):
    return con.execute("SELECT abonados, dias_con_datos FROM activos_7d WHERE hasta = ? AND router = ? "
                       "AND categoria = ?", (hasta, router or "*", categoria)).fetchone()


def _nombres_asn(con):
    nombres = dict(_ASN_FIJOS)
    for a, n, p in con.execute("SELECT asn, nombre, pais FROM asn"):
        nombres[a] = (n, p)
    return nombres


def routers_con_datos(con):
    if not _hay_esquema(con):
        return []
    return [f[0] for f in con.execute("SELECT router FROM total_hora UNION SELECT router FROM archivos "
                                      "WHERE router IS NOT NULL ORDER BY 1")]


def categorias_con_datos(con):
    if not _hay_esquema(con):
        return []
    return [f[0] for f in con.execute("SELECT DISTINCT categoria FROM total_hora ORDER BY 1")]


def resumen(con, categoria, router=None, periodo="7d"):
    dias = _dias(periodo)
    modo = _modo(periodo)
    salida = {"categoria": categoria, "routers": [], "periodo": periodo, "desde": dia_iso(dias[0]),
              "hasta": dia_iso(dias[-1]), "dias_con_datos": 0, "abonados_activos": 0, "abonados_modo": modo,
              "flujos": 0, "bytes_subida": 0, "bytes_bajada": 0, "relacion_bajada_subida": None,
              "ultima_ventana": None, "pendientes": 0}
    if not _hay_esquema(con):
        return salida
    routers, con_datos, (fl, sub, baj) = _totales(con, categoria, router, dias)
    salida.update(routers=routers, dias_con_datos=con_datos, flujos=fl, bytes_subida=sub, bytes_bajada=baj,
                  abonados_activos=_activos(con, categoria, router, dias, modo),
                  relacion_bajada_subida=round(baj / sub, 1) if sub else None)
    de_categoria = [router] if router else [f[0] for f in con.execute(
        "SELECT DISTINCT router FROM total_hora WHERE categoria = ?", (categoria,))]
    if de_categoria:
        marcas = ", ".join("?" * len(de_categoria))
        ultima = con.execute(f"SELECT MAX(ventana) FROM archivos WHERE estado IN ('ok', 'vacio') "
                             f"AND router IN ({marcas})", de_categoria).fetchone()[0]
        salida["ultima_ventana"] = iso(ultima) if ultima is not None else None
        exportadores = {f[0] for f in con.execute(
            f"SELECT DISTINCT exportador FROM archivos WHERE router IN ({marcas})", de_categoria)}
        salida["pendientes"] = pendientes(con, datos_de(con), _ahora(), exportadores)
    return salida


def por_hora(con, categoria, router=None, periodo="hoy"):
    dias = _dias(periodo)
    if not _hay_esquema(con):
        return []
    h0, fin = inicio_dia(dias[0]), inicio_dia(dias[-1]) + 86400
    if periodo == "hoy":
        ahora = int(_ahora())
        fin = min(fin, ahora - ahora % 3600 + 3600)
    cond, params = _cond(categoria, router, h0, fin - 1, col="hora")
    filas = {f[0]: f[1:] for f in con.execute(
        f"SELECT hora, SUM(flujos), SUM(bytes_subida), SUM(bytes_bajada), SUM(abonados_max_ventana) "
        f"FROM total_hora WHERE {cond} GROUP BY hora", params)}
    if not filas:
        return []
    if periodo != "30d":
        salida = []
        for h in range(h0, fin, 3600):
            fl, sub, baj, ab = filas.get(h, (0, 0, 0, 0))
            salida.append({"inicio": iso(h), "paso_segundos": 3600, "flujos": fl, "bytes_subida": sub,
                           "bytes_bajada": baj, "abonados_max_ventana": ab})
        return salida
    por_dia = defaultdict(lambda: [0, 0, 0, 0])
    for h, (fl, sub, baj, ab) in filas.items():
        p = por_dia[dia_de(h)]
        p[0] += fl
        p[1] += sub
        p[2] += baj
        p[3] = max(p[3], ab)
    return [{"inicio": iso(inicio_dia(d)), "paso_segundos": 86400, "flujos": por_dia[d][0],
             "bytes_subida": por_dia[d][1], "bytes_bajada": por_dia[d][2], "abonados_max_ventana": por_dia[d][3]}
            for d in dias]


def top_destinos(con, categoria, router=None, periodo="7d", orden="bytes", limite=50):
    _validar(orden, ("bytes", "abonados"), "orden")
    dias = _dias(periodo)
    if not _hay_esquema(con):
        return []
    modo = _modo(periodo)
    nombres = _nombres_asn(con)
    foto = periodo == "7d" and _hay_foto(con, categoria, router, dias[-1])
    if foto:
        filas = con.execute("SELECT asn, abonados, flujos, bytes_subida, bytes_bajada FROM destino_7d "
                            "WHERE hasta = ? AND router = ? AND categoria = ?",
                            (dias[-1], router or "*", categoria)).fetchall()
        total = foto[0]
    else:
        cond, params = _cond(categoria, router, dias[0], dias[-1])
        sumas = con.execute(f"SELECT asn, SUM(flujos), SUM(bytes_subida), SUM(bytes_bajada) FROM destino_dia "
                            f"WHERE {cond} GROUP BY asn", params).fetchall()
        abonados = _abonados_por(con, "destino_abonado_dia", "destino_dia", ("asn",), categoria, router, dias, modo)
        otros = _max_diario(con, "destino_dia", ("asn",), categoria, router, dias, asn=-1)
        filas = [(asn, otros.get((asn,), 0) if asn == -1 else abonados.get((asn,), 0), fl, sub, baj)
                 for asn, fl, sub, baj in sumas]
        total = _activos(con, categoria, router, dias, modo)
    salida = []
    for asn, ab, fl, sub, baj in filas:
        nombre, pais = nombres.get(asn, (f"AS{asn}", ""))
        salida.append({"asn": asn, "nombre": nombre, "pais": pais, "abonados": ab or 0,
                       "pct_abonados": _pct(ab or 0, total), "flujos": fl or 0, "bytes_subida": sub or 0,
                       "bytes_bajada": baj or 0, "bytes": (sub or 0) + (baj or 0)})
    clave = (lambda f: (-f["bytes"], -f["abonados"])) if orden == "bytes" else (lambda f: (-f["abonados"], -f["bytes"]))
    return sorted(salida, key=clave)[:limite]


def top_puertos(con, categoria, router=None, periodo="7d", sentido="saliente", orden="abonados", limite=80):
    _validar(sentido, SENTIDOS, "sentido")
    _validar(orden, ("abonados", "bytes", "flujos"), "orden")
    dias = _dias(periodo)
    if not _hay_esquema(con):
        return []
    s = SENTIDOS.index(sentido)
    modo = _modo(periodo)
    cond, params = _cond(categoria, router, dias[0], dias[-1], sentido=s)
    sumas = con.execute(f"SELECT proto, puerto, SUM(flujos), SUM(bytes_subida), SUM(bytes_bajada) FROM servicio_dia "
                        f"WHERE {cond} GROUP BY proto, puerto", params).fetchall()
    foto = periodo == "7d" and _hay_foto(con, categoria, router, dias[-1])
    if foto:
        abonados = {(p, pu): a for p, pu, a in con.execute(
            "SELECT proto, puerto, abonados FROM servicio_7d WHERE hasta = ? AND router = ? AND categoria = ? "
            "AND sentido = ?", (dias[-1], router or "*", categoria, s))}
        total = foto[0]
    else:
        abonados = _abonados_por(con, "uso_abonado_dia", "servicio_dia", ("proto", "puerto"), categoria, router,
                                 dias, modo, sentido=s)
        total = _activos(con, categoria, router, dias, modo)
    salida = []
    for proto, puerto, fl, sub, baj in sumas:
        p = servicios.proto_nombre(proto)
        ab = abonados.get((proto, puerto), 0)
        salida.append({"sentido": sentido, "proto": p, "puerto": puerto, "puerto_hasta": servicios.hasta(p, puerto),
                       "etiqueta": servicios.etiqueta(p, puerto), "servicio": servicios.nombre_clave(p, puerto),
                       "abonados": ab, "pct_abonados": _pct(ab, total), "flujos": fl or 0,
                       "bytes_subida": sub or 0, "bytes_bajada": baj or 0})
    claves = {"abonados": lambda f: (-f["abonados"], -f["flujos"]),
              "bytes": lambda f: (-(f["bytes_subida"] + f["bytes_bajada"]), -f["abonados"]),
              "flujos": lambda f: (-f["flujos"], -f["abonados"])}
    return sorted(salida, key=claves[orden])[:limite]


def top_puertos_exactos(con, categoria, router=None, periodo="7d", limite=100):
    """Puertos exactos ≥ 1024 que el catálogo exacto no nombra (cubos -1/-2 y rangos con nombre), por flujos."""
    dias = _dias(periodo)
    if not _hay_esquema(con):
        return []
    cond, params = _cond(categoria, router, dias[0], dias[-1])
    salida = []
    for s, proto, puerto, fl, by, mx in con.execute(
            f"SELECT sentido, proto, puerto, SUM(flujos), SUM(bytes_subida + bytes_bajada), MAX(abonados_max_ventana) "
            f"FROM puerto_dia WHERE {cond} AND puerto >= 1024 GROUP BY sentido, proto, puerto", params):
        p = servicios.proto_nombre(proto)
        if p not in ("tcp", "udp") or (p, puerto) in servicios._EXACTOS:
            continue  # puerto del catálogo exacto: ya sale con nombre en top_puertos
        salida.append({"sentido": SENTIDOS[s], "proto": p, "puerto": puerto, "servicio": servicios.nombre(p, puerto),
                       "flujos": fl or 0, "bytes": by or 0, "abonados_max_ventana": mx or 0})
    return sorted(salida, key=lambda f: (-f["flujos"], f["puerto"]))[:limite]


def top_consumidores(con, categoria, router=None, periodo="7d", orden="bajada", limite=50):
    _validar(orden, ("bajada", "subida", "total", "flujos"), "orden")
    dias = _dias(periodo)
    if not _hay_esquema(con):
        return []
    expr = {"bajada": "bb", "subida": "bs", "total": "bs + bb", "flujos": "fl"}[orden]
    cond, params = _cond(categoria, router, dias[0], dias[-1])
    salida = []
    for r, ab, bs, bb, fl, nd, mf, mi, mp in con.execute(
            f"SELECT router, abonado, SUM(bytes_subida) AS bs, SUM(bytes_bajada) AS bb, SUM(flujos) AS fl, COUNT(*), "
            f"MAX(max_flujos), MAX(max_ips), MAX(max_peers_udp) FROM abonado_dia WHERE {cond} "
            f"GROUP BY router, abonado ORDER BY {expr} DESC, router, abonado LIMIT ?", params + [int(limite)]):
        salida.append({"router": r, "abonado": _ip(ab), "bytes_subida": bs or 0, "bytes_bajada": bb or 0,
                       "flujos": fl or 0, "dias_activo": nd, "max_flujos": mf or 0, "max_ips": mi or 0,
                       "max_peers_udp": mp or 0})
    return salida


def percentiles_abonado(con, categoria, router=None, periodo="7d"):
    """Percentiles por abonado y MINUTO desde los histogramas; max exacto de abonado_dia."""
    dias = _dias(periodo)
    if not _hay_esquema(con):
        return {}
    cond, params = _cond(categoria, router, dias[0], dias[-1])
    hist = defaultdict(list)
    for m, c, n in con.execute(f"SELECT metrica, cubo, SUM(n) FROM hist_dia WHERE {cond} "
                               f"GROUP BY metrica, cubo ORDER BY metrica, cubo", params):
        hist[m].append((c, n))
    if not hist:
        return {}
    maximos = con.execute(f"SELECT {', '.join('MAX(max_' + m + ')' for m in METRICAS)} FROM abonado_dia "
                          f"WHERE {cond}", params).fetchone()
    salida = {}
    for i, m in enumerate(METRICAS):
        cubos = hist.get(m)
        if not cubos:
            continue
        total = sum(n for _, n in cubos)
        mx = maximos[i] if maximos[i] is not None else cota(cubos[-1][0])
        fila = {}
        for p, decimas in ((50, 500), (90, 900), (99, 990), (99.9, 999)):
            k = max(1, -(-decimas * total // 1000))  # ceil(p/100 · N) en enteros (sin error de coma flotante)
            acum = 0
            for c, n in cubos:
                acum += n
                if acum >= k:
                    fila[f"p{p:g}"] = min(cota(c), mx)  # nunca por encima del máximo real
                    break
        fila["max"] = mx
        fila["n"] = total
        salida[m] = fila
    return salida


def _detalle_partes(detalle):
    proto, _, puerto = detalle.partition("/")
    return proto, int(puerto) if puerto.isdigit() else None


def _red_de(tabla, nombres, ip):
    if not ipaddress.IPv4Address(ip).is_global:
        return "no público"
    if tabla is None:
        return ""
    asn = tabla.buscar(ip)
    if not asn:
        return "sin ASN"
    nombre, pais = nombres.get(asn, ("", ""))
    return f"AS{asn} {nombre} ({pais})" if pais else f"AS{asn} {nombre}".strip()


_ASN_WEB = {}


def _tabla_asn(datos):
    """Tabla IP→ASN para las consultas, desde la caché binaria que deja el procesador (sin leer el TSV)."""
    if datos is None:
        return None
    cache = Path(datos) / CACHE_ASN
    try:
        mtime = cache.stat().st_mtime
    except OSError:
        return None
    guardada = _ASN_WEB.get(str(cache))
    if guardada and guardada[0] == mtime:
        return guardada[1]
    from .flujos import TablaAsn
    try:
        tabla = TablaAsn.desde_cache(cache)
    except (OSError, ValueError):
        return None
    _ASN_WEB[str(cache)] = (mtime, tabla)
    return tabla


def senales(con, categoria, router=None, periodo="7d", limite=20):
    dias = _dias(periodo)
    salida = {"sensibles": {}, "reflectores": {}, "barridos": [], "p2p": [], "dns": [], "destinos_no_publicos": []}
    if not _hay_esquema(con):
        return salida
    modo = _modo(periodo)
    cond, params = _cond(categoria, router, dias[0], dias[-1])
    sensibles, reflectores = defaultdict(list), defaultdict(list)
    for tipo, det, r, ab, fl, rem, nv, ult in con.execute(
            f"SELECT tipo, detalle, router, abonado, SUM(flujos), MAX(remotos_max_ventana), SUM(ventanas), MAX(ultima) "
            f"FROM senal_dia WHERE {cond} GROUP BY tipo, detalle, router, abonado", params):
        base = {"router": r, "abonado": _ip(ab)}
        p, puerto = _detalle_partes(det)
        if tipo == "sensible":
            sensibles[f"{det} {servicios.nombre(p, puerto)}".strip()].append(
                {**base, "flujos": fl, "remotos_max_ventana": rem, "ventanas": nv, "ultima": iso(ult)})
        elif tipo == "reflector":
            reflectores[f"{det} entrante (posible reflector)"].append(
                {**base, "flujos": fl, "remotos_max_ventana": rem, "ventanas": nv, "ultima": iso(ult)})
        elif tipo == "barrido":
            salida["barridos"].append({**base, "puerto": det, "servicio": servicios.nombre(p, puerto),
                                       "remotos_max_ventana": rem, "ventanas": nv, "ultima": iso(ult)})
        else:
            salida["p2p"].append({**base, "peers_udp_max": rem, "ventanas": nv, "ultima": iso(ult)})
    def por_flujos(f):
        return -f["flujos"], f["router"], f["abonado"]

    salida["sensibles"] = {k: sorted(v, key=por_flujos)[:limite] for k, v in sorted(sensibles.items())}
    salida["reflectores"] = {k: sorted(v, key=por_flujos)[:limite] for k, v in sorted(reflectores.items())}
    salida["barridos"] = sorted(salida["barridos"], key=lambda f: -f["remotos_max_ventana"])[:limite]
    salida["p2p"] = sorted(salida["p2p"], key=lambda f: -f["peers_udp_max"])[:limite]

    total = _activos(con, categoria, router, dias, modo)
    abonados = _abonados_por(con, "dns_abonado_dia", "dns_dia", ("proto", "puerto", "servidor"), categoria, router,
                             dias, modo)
    tabla, nombres = _tabla_asn(datos_de(con)), _nombres_asn(con)
    dns = []
    for proto, puerto, srv, fl in con.execute(
            f"SELECT proto, puerto, servidor, SUM(flujos) FROM dns_dia WHERE {cond} GROUP BY proto, puerto, servidor "
            f"ORDER BY SUM(flujos) DESC LIMIT ?", params + [int(limite)]):
        ab = abonados.get((proto, puerto, srv), 0)
        dns.append({"proto": servicios.proto_nombre(proto), "puerto": puerto, "servidor": _ip(srv),
                    "red": _red_de(tabla, nombres, srv), "abonados": ab, "pct_abonados": _pct(ab, total),
                    "flujos": fl or 0})
    salida["dns"] = dns
    abonados = _abonados_por(con, "no_publico_abonado_dia", "no_publico_dia", ("red",), categoria, router, dias, modo)
    salida["destinos_no_publicos"] = [
        {"red": f"{_ip(red)}/24", "abonados": abonados.get((red,), 0), "flujos": fl or 0, "bytes": by or 0}
        for red, fl, by in con.execute(
            f"SELECT red, SUM(flujos), SUM(bytes) FROM no_publico_dia WHERE {cond} GROUP BY red "
            f"ORDER BY SUM(flujos) DESC LIMIT ?", params + [int(limite)])]
    return salida


def servicios_categoria(con, categoria, router=None, dias=7):
    """Entrada del firewall: abonados EXACTOS por servicio en los `dias` completos que terminan ayer (≤ 14)."""
    if isinstance(dias, bool) or not isinstance(dias, int) or not 1 <= dias <= 14:
        raise ValueError(f"dias inválido: {dias!r} (de 1 a 14)")
    ayer = sumar_dias(dia_de(_ahora()), -1)
    lista = [sumar_dias(ayer, -i) for i in range(dias - 1, -1, -1)]
    salida = {"categoria": categoria, "routers": [], "desde": dia_iso(lista[0]), "hasta": dia_iso(lista[-1]),
              "dias_con_datos": 0, "abonados_total": 0, "filas": []}
    if not _hay_esquema(con):
        return salida
    routers, con_datos, _ = _totales(con, categoria, router, lista)
    foto = dias == 7 and _hay_foto(con, categoria, router, ayer)
    if foto:
        filas = con.execute("SELECT sentido, proto, puerto, abonados, flujos, bytes, dias_observado FROM servicio_7d "
                            "WHERE hasta = ? AND router = ? AND categoria = ?",
                            (ayer, router or "*", categoria)).fetchall()
        total, con_datos = foto
    else:
        abonados = _presencia(con, "uso_abonado_dia", ("sentido", "proto", "puerto"), categoria, router, lista)
        cond, params = _cond(categoria, router, lista[0], lista[-1])
        filas = [(s, p, pu, abonados.get((s, p, pu), 0), fl, by, nd) for s, p, pu, fl, by, nd in con.execute(
            f"SELECT sentido, proto, puerto, SUM(flujos), SUM(bytes_subida + bytes_bajada), COUNT(DISTINCT dia) "
            f"FROM servicio_dia WHERE {cond} GROUP BY sentido, proto, puerto", params)]
        total = _activos(con, categoria, router, lista, "exacto")
    salida.update(routers=routers, dias_con_datos=con_datos, abonados_total=total)
    for s, proto, puerto, ab, fl, by, nd in filas:
        p = servicios.proto_nombre(proto)
        salida["filas"].append({"sentido": SENTIDOS[s], "proto": p, "puerto": puerto,
                                "puerto_hasta": servicios.hasta(p, puerto), "etiqueta": servicios.etiqueta(p, puerto),
                                "servicio": servicios.nombre_clave(p, puerto), "abonados": ab or 0,
                                "pct_abonados": _pct(ab or 0, total), "flujos": fl or 0, "bytes": by or 0,
                                "dias_observado": nd or 0})
    salida["filas"].sort(key=lambda f: (-f["abonados"], f["sentido"], f["proto"], f["puerto"]))
    return salida


def salud(con, datos, horas=24):
    ahora = _ahora()
    salida = {"exportadores": [], "pendientes": 0, "en_error": 0, "descartados": 0, "ultima_ejecucion": None,
              "disco": estado_disco(datos)}
    if not _hay_esquema(con):
        salida["pendientes"] = pendientes(con, datos, ahora)
        return salida
    desde = int(ahora - horas * 3600)
    for exp, r, ult, n, tot, cat, sec, sub, baj, err in con.execute(
            "SELECT exportador, router, MAX(ventana), COUNT(*), SUM(flujos_total), SUM(flujos_categoria), "
            "SUM(secuencia_perdida), SUM(bytes_subida), SUM(bytes_bajada), SUM(estado = 'error') FROM archivos "
            "WHERE ventana >= ? AND estado != 'descartado' GROUP BY exportador, router ORDER BY exportador, router",
            (desde,)):
        tot, cat = tot or 0, cat or 0
        salida["exportadores"].append({
            "exportador": exp, "router": r, "ultimo_archivo": iso(ult), "archivos": n, "flujos": tot,
            "flujos_categoria": cat, "pct_fuera_categoria": max(0.0, _pct(tot - cat, tot)),
            "secuencia_perdida": sec or 0, "bytes_subida": sub or 0, "bytes_bajada": baj or 0, "errores": err or 0})
    salida["en_error"], salida["descartados"] = con.execute(
        "SELECT COALESCE(SUM(estado = 'error'), 0), COALESCE(SUM(estado = 'descartado'), 0) FROM archivos "
        "WHERE ventana >= ?", (desde,)).fetchone()
    salida["pendientes"] = pendientes(con, datos, ahora)
    ultima = leer_meta(con, "ultima_ejecucion")
    salida["ultima_ejecucion"] = iso(int(ultima)) if ultima else None
    return salida


def ventanas_router(con, router, minutos=60):
    if not _hay_esquema(con):
        return []
    desde = int(_ahora()) - int(minutos) * 60
    return [{"ventana": iso(v), "flujos_total": ft or 0, "flujos_categoria": fc or 0, "bytes_subida": sub or 0,
             "bytes_bajada": baj or 0, "secuencia_perdida": sec or 0, "estado": e}
            for v, ft, fc, sub, baj, sec, e in con.execute(
                "SELECT ventana, flujos_total, flujos_categoria, bytes_subida, bytes_bajada, secuencia_perdida, estado "
                "FROM archivos WHERE router = ? AND ventana >= ? ORDER BY ventana", (router, desde))]


def interfaces_router(con, router, periodo="hoy"):
    dias = _dias(periodo)
    if not _hay_esquema(con):
        return []
    return [{"entrada": e, "salida": s, "flujos": fl or 0, "bytes": by or 0}
            for e, s, fl, by in con.execute(
                "SELECT entrada, salida, SUM(flujos), SUM(bytes) FROM interfaz_dia WHERE router = ? "
                "AND dia BETWEEN ? AND ? GROUP BY entrada, salida ORDER BY SUM(bytes) DESC",
                (router, dias[0], dias[-1]))]
