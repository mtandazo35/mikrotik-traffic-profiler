"""Ingesta NetFlow: lee los archivos cerrados de nfcapd con nfdump (en streaming), clasifica cada flujo por
categoría y sentido, agrega un minuto (un archivo) en memoria y lo guarda en una transacción (mtp/flujos_db.py).

Reglas y decisiones en docs/diseno-netflow.md: clasificación 1.1, métricas 3.3, proceso 4.2, guardián 4.3.
Nunca se carga un archivo entero: nfdump escribe CSV por una tubería y se lee línea a línea.
"""
import array
import bisect
import gzip
import ipaddress
import os
import shutil
import sqlite3
import struct
import subprocess
import sys
import tempfile
import threading
import time
import zlib
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple

from . import flujos_db, servicios
from .analizar import (_PUERTOS_DNS, _REFLECTORES, _SENSIBLES_SALIENTES, _UDP_NO_P2P, _UMBRAL_BARRIDO,
                       _UMBRAL_P2P)

ROTACION = flujos_db.ROTACION
FORMATO = "csv:%pr,%sa,%sp,%da,%dp,%flg,%ipkt,%ibyt,%fl,%in,%out"
# Entradas de diccionario + miembros de conjuntos de un archivo. Medido en el tope (mezcla P2P de 3000
# abonados y TCP de 16 000): 270-285 MiB de montículo Python; con el intérprete, caché SQLite (64 MiB), tabla
# ASN y nfdump hijo queda ≈ 420 MiB, bajo MemoryHigh=600M. Más = el router exporta de más (¿la WAN?).
TOPE_CLAVES = 2_000_000
LIMITE_NFDUMP = 600       # segundos; el vigilante mata a nfdump después
MAX_INTENTOS = 3          # arranques de un archivo antes de abandonarlo (estado error)
EN_CURSO = "en curso: si se queda así, el procesador murió con este archivo (¿MemoryMax?)"
ARCHIVO_ASN = "ip2asn-v4.tsv.gz"
SALIENTE, ENTRANTE, INTERNA = 0, 1, 2
_PETICIONES_ICMP = {8, 13, 15, 17}  # eco, marca de tiempo, información, máscara
_NUM = {"tcp": 6, "udp": 17}
_SENSIBLES = {(_NUM[p], puerto) for p, puerto in _SENSIBLES_SALIENTES}
_DNS = {(_NUM[p], puerto) for p, puerto in _PUERTOS_DNS}
_SIN_BARRIDO = {(6, 80), (6, 443), (17, 443)}
_TIPO_ARRAY = "I" if array.array("I").itemsize == 4 else "L"
_MAGIA_CACHE = b"MTPASN1\0"

_es_servicio = lru_cache(maxsize=None)(servicios.es_servicio)
_clave = lru_cache(maxsize=None)(servicios.clave)
_proto = lru_cache(maxsize=None)(servicios.proto_nombre)


class Flujo(NamedTuple):
    proto: int
    src: int
    sport: int
    dst: int
    dport: int  # en ICMP, el tipo (nfdump lo imprime como tipo.código)
    flags: str
    paquetes: int
    bytes: int
    flujos: int
    entrada: int
    salida: int


class Observacion(NamedTuple):
    categoria: str
    sentido: int  # SALIENTE, ENTRANTE, INTERNA
    lado: str     # "src": el abonado es el origen (bytes de subida); "dst": el destino (bytes de bajada)
    abonado: int
    remoto: int
    puerto: int   # puerto de servicio (0 si no es tcp/udp)
    subida: int
    bajada: int

    @property
    def peticion(self):
        """Registro del lado cliente al lado servidor."""
        return (self.sentido == SALIENTE and self.lado == "src") or (self.sentido == ENTRANTE and self.lado == "dst")


def _ip(texto):
    partes = texto.strip().split(".")
    if len(partes) != 4:
        return None
    try:
        a, b, c, d = (int(x) for x in partes)
    except ValueError:
        return None
    if not (0 <= a <= 255 and 0 <= b <= 255 and 0 <= c <= 255 and 0 <= d <= 255):
        return None
    return (a << 24) | (b << 16) | (c << 8) | d


def leer_linea(linea):
    """Flujo de una línea CSV de nfdump (FORMATO), o None si es la cabecera, IPv6 o está mal formada."""
    partes = linea.strip().split(",")
    if len(partes) != 11 or not partes[0][:1].isdigit():
        return None
    src, dst = _ip(partes[1]), _ip(partes[3])
    if src is None or dst is None:
        return None
    try:
        dp = partes[4]
        dport = int(dp.partition(".")[0]) if "." in dp else int(dp)
        return Flujo(int(partes[0]), src, int(partes[2]), dst, dport, partes[5].strip(), int(partes[6]),
                     int(partes[7]), int(partes[8]), int(partes[9]), int(partes[10]))
    except ValueError:
        return None


def filtro_nfdump(cidrs):
    """Filtro de nfdump con los rangos de abonados: lo demás se descarta en C, sin pasar por Python."""
    return " or ".join(f"net {ipaddress.ip_network(c, strict=False)}" for c in cidrs)


class Redes:
    """Rangos de las categorías de un router; categoria_de(ip) por búsqueda binaria."""

    def __init__(self, categorias):
        rangos = []
        for cat, cidrs in (categorias or {}).items():
            redes = [ipaddress.ip_network(c, strict=False) for c in cidrs]
            for red in ipaddress.collapse_addresses(r for r in redes if r.version == 4):
                rangos.append((int(red.network_address), int(red.broadcast_address), cat, str(red)))
        rangos.sort()
        self.inicios = [r[0] for r in rangos]
        self.finales = [r[1] for r in rangos]
        self.categorias = [r[2] for r in rangos]
        self.cidrs = [r[3] for r in rangos]

    def categoria_de(self, ip):
        i = bisect.bisect_right(self.inicios, ip) - 1
        if i >= 0 and ip <= self.finales[i]:
            return self.categorias[i]
        return None


def _sentido(fl, lado):
    """(sentido, puerto de servicio) según las reglas de 1.1."""
    if fl.proto in (6, 17):
        ap, rp = (fl.sport, fl.dport) if lado == "src" else (fl.dport, fl.sport)
        p = _proto(fl.proto)
        sa, sr = _es_servicio(p, ap), _es_servicio(p, rp)
        if sr and not sa:
            return SALIENTE, rp
        if sa and not sr:
            return ENTRANTE, ap
        return (SALIENTE, rp) if rp <= ap else (ENTRANTE, ap)  # los dos o ninguno: el menor gana
    if fl.proto == 1:
        # petición: saliente si la manda el abonado; respuesta/error: saliente si la recibe el abonado
        return (SALIENTE, 0) if (fl.dport in _PETICIONES_ICMP) == (lado == "src") else (ENTRANTE, 0)
    return SALIENTE, 0  # GRE, ESP, AH…


def observaciones(fl, redes):
    """0, 1 o 2 observaciones de un flujo: una por cada lado que es abonado de una categoría del router."""
    cs, cd = redes.categoria_de(fl.src), redes.categoria_de(fl.dst)
    if cs is None and cd is None:
        return []
    if cs is not None and cs == cd:
        return [Observacion(cs, INTERNA, "src", fl.src, fl.dst, _sentido(fl, "src")[1], fl.bytes, 0)]
    salida = []
    if cs is not None:
        s, puerto = _sentido(fl, "src")
        salida.append(Observacion(cs, s, "src", fl.src, fl.dst, puerto, fl.bytes, 0))
    if cd is not None:
        s, puerto = _sentido(fl, "dst")
        salida.append(Observacion(cd, s, "dst", fl.dst, fl.src, puerto, 0, fl.bytes))
    return salida


def router_por_exportador(inv, ip):
    """Router cuyo `exportador` es la IP; si no, el router sin `exportador` cuyo `host` es la IP."""
    routers = (inv or {}).get("routers", {})
    for nombre, r in routers.items():
        if r.get("exportador") == ip:
            return nombre
    for nombre, r in routers.items():
        if not r.get("exportador") and r.get("host") == ip:
            return nombre
    return None


class TablaAsn:
    """IP→ASN con el TSV de iptoasn.com en arrays (≈ 6 MB). El ASN 0 (no enrutado) se descarta."""

    def __init__(self, ruta=None):
        self.inicios = array.array(_TIPO_ARRAY)
        self.finales = array.array(_TIPO_ARRAY)
        self.asns = array.array(_TIPO_ARRAY)
        self._nombres = {}
        if ruta is not None:
            self._leer(ruta)

    def _leer(self, ruta):
        abrir = gzip.open if str(ruta).endswith(".gz") else open
        ordenado, ultimo = True, -1
        with abrir(ruta, "rt", encoding="utf-8", errors="replace") as f:
            for linea in f:
                partes = linea.rstrip("\n").split("\t")
                if len(partes) < 5:
                    continue
                try:
                    asn = int(partes[2])
                    a, b = int(ipaddress.IPv4Address(partes[0])), int(ipaddress.IPv4Address(partes[1]))
                except ValueError:
                    continue
                if asn == 0:
                    continue
                ordenado = ordenado and a > ultimo
                ultimo = a
                self.inicios.append(a)
                self.finales.append(b)
                self.asns.append(asn)
                self._nombres.setdefault(asn, (partes[4].strip(), partes[3].strip()))
        if not ordenado:
            filas = sorted(zip(self.inicios, self.finales, self.asns))
            self.inicios = array.array(_TIPO_ARRAY, (f[0] for f in filas))
            self.finales = array.array(_TIPO_ARRAY, (f[1] for f in filas))
            self.asns = array.array(_TIPO_ARRAY, (f[2] for f in filas))

    def __len__(self):
        return len(self.inicios)

    def buscar(self, ip):
        i = bisect.bisect_right(self.inicios, ip) - 1
        if i >= 0 and ip <= self.finales[i]:
            return self.asns[i]
        return 0

    def nombres(self):
        """(asn, nombre, pais) de cada ASN del TSV."""
        return ((a, n, p) for a, (n, p) in sorted(self._nombres.items()))

    def guardar_cache(self, ruta):
        """Arrays en binario: el siguiente minuto carga en milisegundos en vez de leer el TSV."""
        ruta = Path(ruta)
        temporal = ruta.with_name(ruta.name + ".parcial")
        with open(temporal, "wb") as f:
            f.write(_MAGIA_CACHE + struct.pack("<Q", len(self.inicios)))
            for a in (self.inicios, self.finales, self.asns):
                a.tofile(f)
        os.replace(temporal, ruta)

    @classmethod
    def desde_cache(cls, ruta):
        tabla = cls()
        with open(ruta, "rb") as f:
            if f.read(len(_MAGIA_CACHE)) != _MAGIA_CACHE:
                raise ValueError(f"{ruta}: no es una caché de ASN")
            (n,) = struct.unpack("<Q", f.read(8))
            for a in (tabla.inicios, tabla.finales, tabla.asns):
                a.fromfile(f, n)  # EOFError (ValueError no) si está truncada
        return tabla


def cargar_asn(datos, con):
    """Tabla IP→ASN para procesar; si el TSV cambió, actualiza los nombres en la base y la caché binaria."""
    tsv = Path(datos) / ARCHIVO_ASN
    if not tsv.exists():
        return None
    mtime = str(int(tsv.stat().st_mtime))
    cache = Path(datos) / flujos_db.CACHE_ASN

    def desde_cache():
        try:
            return TablaAsn.desde_cache(cache) if cache.exists() else None
        except (OSError, ValueError, EOFError):
            return None

    malo = flujos_db.leer_meta(con, "asn_malo") == mtime
    if flujos_db.leer_meta(con, "asn_mtime") == mtime or malo:
        tabla = desde_cache()  # al día; o el TSV nuevo está dañado y vale la caché del anterior
        if tabla is not None or malo:
            return tabla
    try:
        tabla = TablaAsn(tsv)
        if not len(tabla):
            raise ValueError("sin rangos")
    except (OSError, EOFError, zlib.error, ValueError, UnicodeError) as e:
        # gz truncado o dañado: no se vuelve a leer este mismo archivo cada minuto
        print(f"aviso: {tsv} dañado ({type(e).__name__}: {e}); se usa la tabla anterior si la hay",
              file=sys.stderr)
        flujos_db.poner_meta(con, "asn_malo", mtime)
        return desde_cache()
    flujos_db.actualizar_asn(con, tabla.nombres(), mtime)
    try:
        tabla.guardar_cache(cache)
    except OSError as e:
        print(f"aviso: no se pudo guardar {cache}: {e}", file=sys.stderr)
    return tabla


@lru_cache(maxsize=65536)
def _es_global(ip):
    return ipaddress.IPv4Address(ip).is_global


def _detalle(p, puerto):
    return f"{p}/{puerto}" if p in ("tcp", "udp") else p


def _sumar(d, k, *valores):
    f = d.get(k)
    if f is None:
        d[k] = list(valores)
    else:
        for i, v in enumerate(valores):
            f[i] += v


class _Metricas:
    """Lo de un abonado en un minuto, solo de sus registros de petición saliente."""
    __slots__ = ("tuplas", "udp", "ips", "puertos", "peers", "tcp_nuevas", "syn", "por_puerto")

    def __init__(self):
        self.tuplas, self.ips, self.puertos, self.peers = set(), set(), set(), set()
        self.udp = self.tcp_nuevas = self.syn = 0
        self.por_puerto = {}  # proto << 16 | rp -> [registros, {remotos}]  (barridos)

    def valores(self):
        """En el orden de flujos_db.METRICAS."""
        return (len(self.tuplas), self.tcp_nuevas, self.udp, len(self.ips), len(self.puertos), len(self.peers),
                self.syn)


class DemasiadoGrande(Exception):
    pass


class ErrorNfdump(Exception):
    pass


class Agregador:
    """Todo lo de un archivo (un minuto de un router) en memoria; filas() lo deja listo para flujos_db."""

    def __init__(self, router, ventana, asn=None):
        self.router, self.ventana = router, ventana
        self.dia = flujos_db.dia_de(ventana)
        self.hora = ventana - ventana % 3600
        self._asn = asn.buscar if asn is not None else None
        self.lineas = self.flujos = self.subida = self.bajada = self.omitidos = self.elementos = 0
        self.tot, self.itf, self.sv, self.pt, self.uso, self.dest = {}, {}, {}, {}, {}, {}
        self.dns, self.np, self.ab, self.met, self.sen, self._remotos = {}, {}, {}, {}, {}, {}
        self._abonados = {}  # entero -> el mismo objeto entero: los conjuntos comparten uno por abonado

    def claves(self):
        """Entradas de diccionario + miembros de todos los conjuntos: lo que crece con el archivo."""
        return (self.elementos + len(self.tot) + len(self.itf) + len(self.sv) + len(self.pt) + len(self.uso)
                + len(self.dest) + len(self.dns) + len(self.np) + len(self.ab) + len(self.met) + len(self.sen)
                + len(self._remotos) + len(self._abonados))

    def _agregar(self, conjunto, x):
        n = len(conjunto)
        conjunto.add(x)
        self.elementos += len(conjunto) - n

    def _remoto(self, ip):
        """(asn, público, ip) con la ip como objeto único (internado: un solo entero por IP remota)."""
        r = self._remotos.get(ip)
        if r is None:
            publico = _es_global(ip)
            r = self._remotos[ip] = ((self._asn(ip) if publico and self._asn else 0), publico, ip)
        return r

    def _senal(self, cat, tipo, detalle, ab, n, remoto):
        s = self.sen.get((cat, tipo, detalle, ab))
        if s is None:
            s = self.sen[(cat, tipo, detalle, ab)] = [0, set()]
        s[0] += n
        self._agregar(s[1], remoto)

    def agregar(self, fl, obs):
        self.lineas += 1
        self.flujos += fl.flujos
        _sumar(self.itf, (fl.entrada, fl.salida), fl.flujos, fl.bytes)
        for o in obs:
            self._observacion(fl, o)

    def _observacion(self, fl, o):
        cat, n, pk, sub, baj = o.categoria, fl.flujos, fl.paquetes, o.subida, o.bajada
        ab = self._abonados.setdefault(o.abonado, o.abonado)
        proto = fl.proto
        p = _proto(proto)
        k = _clave(p, o.puerto)
        self.subida += sub
        self.bajada += baj
        t = self.tot.get(cat)
        if t is None:
            t = self.tot[cat] = [0, 0, 0, 0, set()]
        t[0] += n
        t[1] += pk
        t[2] += sub
        t[3] += baj
        self._agregar(t[4], ab)
        for d, clave in ((self.sv, (cat, o.sentido, proto, k)), (self.pt, (cat, o.sentido, proto, o.puerto))):
            f = d.get(clave)
            if f is None:
                f = d[clave] = [0, 0, 0, 0, set()]
            f[0] += n
            f[1] += pk
            f[2] += sub
            f[3] += baj
            self._agregar(f[4], ab)
        _sumar(self.uso, (cat, o.sentido, proto, k, ab), n, sub + baj)
        _sumar(self.ab, (cat, ab), n, pk, sub, baj)
        if o.sentido == INTERNA:
            return
        asn, publico, remoto = self._remoto(o.remoto)
        _sumar(self.dest, (cat, asn, ab), n, sub, baj)
        if not publico:
            _sumar(self.np, (cat, remoto & 0xFFFFFF00, ab), n, sub + baj)
        if o.sentido == SALIENTE and o.lado == "src":
            self._peticion(fl, o, cat, ab, p, remoto)
        elif o.sentido == ENTRANTE and proto == 17 and o.puerto in _REFLECTORES:
            self._senal(cat, "reflector", f"udp/{o.puerto}", ab, n, remoto)

    def _peticion(self, fl, o, cat, ab, p, remoto):
        m = self.met.get((cat, ab))
        if m is None:
            m = self.met[(cat, ab)] = _Metricas()
        proto, rp, n = fl.proto, o.puerto, fl.flujos
        # 5-tupla y (proto, puerto) como un solo entero: ocupan bastante menos que una tupla de Python
        antes = len(m.tuplas)
        m.tuplas.add((proto << 64) | (fl.sport << 48) | (remoto << 16) | fl.dport)
        if len(m.tuplas) > antes:
            self.elementos += 1
            if proto == 17:
                m.udp += 1
        if proto == 6 and "S" in fl.flags:
            m.tcp_nuevas += 1
            if "A" not in fl.flags:
                m.syn += 1
        clave_puerto = (proto << 16) | rp
        self._agregar(m.ips, remoto)
        self._agregar(m.puertos, clave_puerto)
        if proto == 17 and rp >= 1024 and rp not in _UDP_NO_P2P:
            self._agregar(m.peers, remoto)
        pp = m.por_puerto.get(clave_puerto)
        if pp is None:
            pp = m.por_puerto[clave_puerto] = [0, set()]
        pp[0] += n
        self._agregar(pp[1], remoto)
        if (proto, rp) in _DNS:
            _sumar(self.dns, (cat, proto, rp, remoto, ab), n)
        if (proto, rp) in _SENSIBLES:
            self._senal(cat, "sensible", _detalle(p, rp), ab, n, remoto)

    def filas(self):
        """{tabla: filas} en el orden de columnas de flujos_db.TABLAS_ARCHIVO. Las tablas grandes van como
        generadores (executemany los consume sin copiar el minuto entero en listas): se recorren una sola vez."""
        d, r, v = self.dia, self.router, self.ventana
        f = {"total_hora": [(self.hora, r, c, t[0], t[1], t[2], t[3], 1, len(t[4])) for c, t in self.tot.items()],
             "interfaz_dia": [(d, r, e, s, x[0], x[1]) for (e, s), x in self.itf.items()],
             "servicio_dia": ((d, r, *k, x[0], x[1], x[2], x[3], len(x[4])) for k, x in self.sv.items()),
             "puerto_dia": ((d, r, *k, x[0], x[1], x[2], x[3], len(x[4])) for k, x in self.pt.items()),
             "uso_abonado_dia": ((d, r, *k, x[0], x[1]) for k, x in self.uso.items()),
             "destino_abonado_dia": ((d, r, *k, x[0], x[1], x[2]) for k, x in self.dest.items()),
             "dns_abonado_dia": ((d, r, *k, x[0]) for k, x in self.dns.items()),
             "no_publico_abonado_dia": ((d, r, *k, x[0], x[1]) for k, x in self.np.items())}
        destino, dns, np_ = {}, {}, {}
        for (c, asn, _), x in self.dest.items():
            _sumar(destino, (c, asn), *x)
        for (c, pr, pu, srv, _), x in self.dns.items():
            _sumar(dns, (c, pr, pu, srv), *x)
        for (c, red, _), x in self.np.items():
            _sumar(np_, (c, red), *x)
        f["destino_dia"] = [(d, r, *k, *x) for k, x in destino.items()]
        f["dns_dia"] = [(d, r, *k, *x) for k, x in dns.items()]
        f["no_publico_dia"] = [(d, r, *k, *x) for k, x in np_.items()]
        ceros = (0,) * len(flujos_db.METRICAS)
        f["abonado_dia"] = ((d, r, c, ab, x[0], x[1], x[2], x[3], 1,
                             *(self.met[(c, ab)].valores() if (c, ab) in self.met else ceros))
                            for (c, ab), x in self.ab.items())
        hist = {}
        senales = [(d, r, c, tipo, det, ab, x[0], 1, len(x[1]), v) for (c, tipo, det, ab), x in self.sen.items()]
        for (c, ab), m in self.met.items():
            # un abonado activo (con alguna petición saliente) = una observación por métrica, ceros incluidos
            for metrica, valor in zip(flujos_db.METRICAS, m.valores()):
                k = (c, metrica, flujos_db.cubo(valor))
                hist[k] = hist.get(k, 0) + 1
            for clave_puerto, (n, remotos) in m.por_puerto.items():
                pr, rp = clave_puerto >> 16, clave_puerto & 0xFFFF
                if len(remotos) >= _UMBRAL_BARRIDO and (pr, rp) not in _SIN_BARRIDO:
                    senales.append((d, r, c, "barrido", _detalle(_proto(pr), rp), ab, n, 1, len(remotos), v))
            if len(m.peers) >= _UMBRAL_P2P:
                senales.append((d, r, c, "p2p", "", ab, m.udp, 1, len(m.peers), v))
        f["hist_dia"] = [(d, r, *k, n) for k, n in hist.items()]
        f["senal_dia"] = senales
        return f


# ---------- nfdump ----------

def _estadistica(nfdump, ruta):
    """`nfdump -I`: Flows, Bytes y Sequence failures del archivo, sin leer los registros."""
    try:
        r = subprocess.run([*nfdump, "-I", "-r", str(ruta)], capture_output=True, text=True, encoding="utf-8",
                           errors="replace", timeout=120)
    except subprocess.TimeoutExpired:
        raise ErrorNfdump("nfdump -I no terminó en 120 s")
    if r.returncode != 0:
        raise ErrorNfdump((r.stderr or r.stdout or f"nfdump -I salió con {r.returncode}")[-400:])
    salida = {}
    for linea in r.stdout.splitlines():
        clave, _, valor = linea.partition(":")
        valor = valor.strip()
        if valor.isdigit():
            salida[clave.strip()] = int(valor)
    return salida


def _leer_flujos(nfdump, ruta, redes, ag, tope):
    """nfdump en una tubería, línea a línea; la memoria la marca el agregador, no el archivo."""
    args = [*nfdump, "-r", str(ruta), "-q", "-N", "-o", FORMATO, filtro_nfdump(redes.cidrs)]
    vencido = threading.Event()
    with tempfile.TemporaryFile() as err:
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=err, text=True, encoding="ascii", errors="replace")

        def matar():
            vencido.set()
            p.kill()

        vigilante = threading.Timer(LIMITE_NFDUMP, matar)
        vigilante.daemon = True
        vigilante.start()
        try:
            for linea in p.stdout:
                if not linea[:1].isdigit():
                    continue  # cabecera (nfdump siempre la imprime)
                fl = leer_linea(linea)
                if fl is None:
                    ag.omitidos += 1  # IPv6 o mal formada
                    continue
                ag.agregar(fl, observaciones(fl, redes))
                if not ag.lineas & 1023 and ag.claves() > tope:
                    raise DemasiadoGrande()
            rc = p.wait()
        except BaseException:
            p.kill()
            p.wait()
            raise
        finally:
            vigilante.cancel()
            p.stdout.close()
        if vencido.is_set():
            raise ErrorNfdump(f"nfdump no terminó en {LIMITE_NFDUMP} s")
        if ag.claves() > tope:
            raise DemasiadoGrande()
        if rc != 0:
            err.seek(0)
            texto = err.read().decode("utf-8", "replace").strip()
            raise ErrorNfdump((texto or f"nfdump salió con {rc}")[-400:])


# ---------- guardián de disco ----------

def _pid_vivo(pid):
    if os.name == "posix":
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
        except OSError:
            return False
        return True
    try:  # Windows (solo pruebas): os.kill(pid, 0) enviaría Ctrl+C
        import ctypes
        k32 = ctypes.windll.kernel32
        k32.OpenProcess.restype = ctypes.c_void_p
        k32.CloseHandle.argtypes = [ctypes.c_void_p]
        k32.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_ulong)]
        h = k32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
        if not h:
            return False
        try:
            codigo = ctypes.c_ulong()
            k32.GetExitCodeProcess(h, ctypes.byref(codigo))
            return codigo.value == 259  # STILL_ACTIVE
        finally:
            k32.CloseHandle(h)
    except (AttributeError, OSError):
        return True  # ante la duda, no se borra


def guardian(datos, con, *, ahora=None, uso=shutil.disk_usage, limites=None):
    """Mantiene data/nfcapd dentro de su presupuesto (sección 4.3). El colector no tiene límite propio."""
    datos = Path(datos)
    t = time.time() if ahora is None else ahora
    lim = flujos_db.limites_disco(limites)
    base = datos / "nfcapd"
    crudos = flujos_db.listar_crudo(datos)  # de la ventana más vieja a la más nueva
    est = flujos_db.estados(con)
    crudo_total = flujos_db.peso(base) if base.is_dir() else 0
    borrados, descartados = [], []
    quedan = list(crudos)

    def estado(c):
        e = est.get(c.ruta)
        return e["estado"] if e else None

    def libre():
        return flujos_db.libre_pct(datos, uso)

    def borrar(c):
        nonlocal crudo_total
        try:
            c.camino.unlink()
        except FileNotFoundError:
            pass
        except OSError as e:
            print(f"aviso: no se pudo borrar {c.camino}: {e}", file=sys.stderr)
            return False
        crudo_total -= c.tam
        quedan.remove(c)
        return True

    # 1) procesado más viejo que CRUDO_HORAS; el de exportadores desconocidos, a la hora
    for c in list(quedan):
        e = estado(c)
        if (e == "desconocido" and c.ventana < t - 3600) or (e in flujos_db.FINALES and
                                                            c.ventana < t - lim["crudo_horas"] * 3600):
            if borrar(c):
                borrados.append(c.ruta)
    # 2) tope de tamaño del crudo: procesados del más viejo al más nuevo hasta el 90 %
    tope = lim["crudo_max_gb"] * 1e9
    if crudo_total > tope:
        for c in [c for c in quedan if estado(c) in flujos_db.FINALES]:
            if crudo_total <= 0.9 * tope:
                break
            if borrar(c):
                borrados.append(c.ruta)
    # 3) poco disco libre: procesados aunque sean recientes
    if libre() < lim["min_libre_pct"]:
        for c in [c for c in quedan if estado(c) in flujos_db.FINALES]:
            if libre() >= lim["min_libre_pct"] + 5:
                break
            if borrar(c):
                borrados.append(c.ruta)
    # 4) emergencia: sin procesar, del más viejo, registrados como descartados
    critico = libre() < lim["critico_pct"]
    if critico:
        for c in [c for c in quedan if estado(c) not in flujos_db.FINALES]:
            if libre() >= lim["critico_pct"] + 2:
                break
            if borrar(c):
                descartados.append(c)
        print(f"ERROR: disco crítico ({libre():.1f} % libre): {len(descartados)} archivos NetFlow sin procesar "
              f"descartados", file=sys.stderr)
    # 5) restos de una caída: nfcapd.current.<pid> de un proceso que ya no existe
    if base.is_dir():
        for carpeta in base.iterdir():
            if not carpeta.is_dir():
                continue
            for f in carpeta.glob("nfcapd.current.*"):
                pid = f.name.rsplit(".", 1)[-1]
                try:
                    viejo = f.stat().st_mtime < t - 600
                except OSError:
                    continue
                if pid.isdigit() and viejo and not _pid_vivo(int(pid)):
                    try:
                        tam = f.stat().st_size
                        f.unlink()
                        crudo_total -= tam
                    except OSError:
                        pass
    # 6) dejar constancia en la base
    con.execute("BEGIN IMMEDIATE")
    try:
        flujos_db.marcar_borrados(con, borrados, t)
        flujos_db.descartar(con, descartados, t)
        flujos_db.poner_meta(con, "disco_critico", "1" if critico else "0")
        con.execute("COMMIT")
    except BaseException:
        con.execute("ROLLBACK")
        raise
    pct = libre()
    return {"borrados": len(borrados) + len(descartados), "descartados": len(descartados),
            "libre_pct": round(pct, 1), "crudo_bytes": max(0, crudo_total), "estado": flujos_db.nivel_disco(pct, lim)}


# ---------- procesar ----------

@contextmanager
def _candado(ruta):
    """flock no bloqueante: si otro procesador está corriendo, se devuelve False. En Windows no hay candado."""
    try:
        import fcntl
    except ImportError:
        yield True
        return
    f = open(ruta, "a")
    try:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            tomado = True
        except OSError:
            tomado = False
        yield tomado
    finally:
        f.close()


def _un_archivo(con, c, previo, inventario, asn, nfdump, tope, t):
    """Procesa un archivo y devuelve su estado final ('ok', 'vacio', 'desconocido', 'reintentar' o 'error')."""
    inicio = time.monotonic()
    intentos = (previo or {}).get("intentos") or 0
    router = router_por_exportador(inventario, c.exportador)
    fila = {"ruta": c.ruta, "exportador": c.exportador, "router": router, "ventana": c.ventana, "tam": c.tam,
            "mtime": c.mtime, "intentos": intentos + 1, "procesado": int(t)}
    if router is None:
        try:
            stat = _estadistica(nfdump, c.camino)
        except (ErrorNfdump, OSError):
            stat = {}
        fila.update(estado="desconocido", flujos_total=stat.get("Flows", 0), bytes_total=stat.get("Bytes"),
                    secuencia_perdida=stat.get("Sequence failures"), segundos=round(time.monotonic() - inicio, 3))
        flujos_db.registrar_desconocido(con, fila)
        return "desconocido"
    if intentos >= MAX_INTENTOS:
        # sigue en 'reintentar' tras MAX_INTENTOS arranques: el proceso murió a mitad (SIGKILL por MemoryMax,
        # corte…). Se abandona para no bloquear a los que vienen detrás.
        fila.update(estado="error", intentos=intentos, segundos=0.0,
                    error=f"abandonado tras {intentos} intentos sin terminar ({(previo or {}).get('error') or ''})"[-400:])
        flujos_db.registrar_fallo(con, fila)
        print(f"{c.ruta}: error: {fila['error']}", file=sys.stderr)
        return "error"
    # checkpoint del intento ANTES de abrir nfdump (transacción propia): si el proceso muere, queda contado
    flujos_db.registrar_fallo(con, {**fila, "estado": "reintentar", "error": EN_CURSO})
    ag = None
    try:
        ag = Agregador(router, c.ventana, asn() if callable(asn) else asn)
        stat = _estadistica(nfdump, c.camino)
        redes = Redes(inventario["routers"][router].get("categorias"))
        if redes.cidrs:
            _leer_flujos(nfdump, c.camino, redes, ag, tope)
        estado = "ok" if ag.lineas else "vacio"
        fila.update(estado=estado, flujos_total=stat.get("Flows"), bytes_total=stat.get("Bytes"),
                    secuencia_perdida=stat.get("Sequence failures"), flujos_categoria=ag.flujos,
                    bytes_subida=ag.subida, bytes_bajada=ag.bajada, omitidos=ag.omitidos,
                    segundos=round(time.monotonic() - inicio, 3), error=None)
        flujos_db.guardar_archivo(con, fila, ag.filas() if ag.lineas else {})
        return estado
    except DemasiadoGrande:
        fila.update(estado="error", error="demasiado grande: revisar interfaces= del router")
    except (ErrorNfdump, OSError, ValueError, EOFError, sqlite3.Error) as e:
        fila.update(estado="reintentar" if intentos + 1 < MAX_INTENTOS else "error",
                    error=str(e)[-400:] or type(e).__name__)
    except Exception as e:  # noqa: BLE001 — un archivo raro no puede parar la cola; queda registrado con su tipo
        ag = None  # MemoryError: soltar el minuto antes de seguir
        fila.update(estado="reintentar" if intentos + 1 < MAX_INTENTOS else "error",
                    error=f"{type(e).__name__}: {e}"[-400:])
    ag = None  # soltar la memoria del minuto antes de seguir
    fila["segundos"] = round(time.monotonic() - inicio, 3)
    flujos_db.registrar_fallo(con, fila)
    print(f"{c.ruta}: {fila['estado']}: {fila['error']}", file=sys.stderr)
    return fila["estado"]


def procesar(datos, inventario, *, ahora=None, espera=True, max_segundos=600, nfdump=("nfdump",),
             tope_claves=None, uso=shutil.disk_usage, limites=None):
    """Una ejecución del procesador (sección 4.2). `nfdump` = prefijo de argv (en pruebas, el falso)."""
    datos = Path(datos)
    datos.mkdir(parents=True, exist_ok=True)
    tope = TOPE_CLAVES if tope_claves is None else tope_claves
    res = {"procesados": 0, "vacios": 0, "errores": 0, "desconocidos": 0, "pendientes": 0, "dias_cerrados": [],
           "guardian": {}}
    with _candado(datos / "flujos.lock") as tomado:
        if not tomado:
            res["omitido"] = "otro procesador en curso"
            return res
        con = flujos_db.abrir(datos / flujos_db.RUTA_RELATIVA)
        try:
            flujos_db.crear_esquema(con)

            def reloj():
                return time.time() if ahora is None else ahora

            tabla = []

            def asn():  # la tabla ASN se carga solo si hay algo que procesar; si falla, se sigue sin ASN
                if not tabla:
                    try:
                        tabla.append(cargar_asn(datos, con))
                    except Exception as e:  # noqa: BLE001 — sin ASN los destinos van a 0, pero se procesa
                        print(f"aviso: tabla ASN no disponible ({type(e).__name__}: {e}); destinos sin ASN",
                              file=sys.stderr)
                        tabla.append(None)
                return tabla[0]

            res["guardian"] = guardian(datos, con, ahora=reloj(), uso=uso, limites=limites)
            est = flujos_db.estados(con)
            candidatos = []
            for c in flujos_db.listar_crudo(datos):
                e = est.get(c.ruta)
                if e and e["estado"] in flujos_db.FINALES:
                    if e["estado"] == "ok" and (e["tam"], e["mtime"]) != (c.tam, c.mtime) and not e["error"]:
                        texto = "cambió después de procesarlo; no se vuelve a sumar"
                        print(f"aviso: {c.ruta}: {texto}", file=sys.stderr)
                        flujos_db.marcar_cambiado(con, c.ruta, texto)
                    continue
                if espera and not flujos_db.listo(c, reloj()):
                    continue
                candidatos.append((c, e))
            inicio = time.monotonic()
            for i, (c, e) in enumerate(candidatos):
                if time.monotonic() - inicio > max_segundos:
                    res["pendientes"] = len(candidatos) - i
                    break
                if i and not i % 20:
                    res["guardian"] = guardian(datos, con, ahora=reloj(), uso=uso, limites=limites)
                if not c.camino.exists():
                    continue  # lo borró el guardián (disco crítico)
                estado = _un_archivo(con, c, e, inventario, asn, nfdump, tope, reloj())
                clave = {"ok": "procesados", "vacio": "vacios", "desconocido": "desconocidos"}.get(estado, "errores")
                res[clave] += 1
            t = reloj()
            res["dias_cerrados"] = [flujos_db.dia_iso(d) for d in flujos_db.cerrar_dias(con, t)]
            if flujos_db.leer_meta(con, "ultima_retencion") != str(flujos_db.dia_de(t)):
                flujos_db.retencion(con, t)
            flujos_db.poner_meta(con, "ultima_ejecucion", int(t))
            con.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchall()
        finally:
            con.close()
    return res
