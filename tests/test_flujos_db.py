import gzip
import json
import os
import random
import sys
import tempfile
import time
import unittest
from collections import namedtuple
from pathlib import Path
from unittest import mock

from mtp import flujos, flujos_db
from tests import emisor_netflow

FALSO = (sys.executable, str(Path(__file__).with_name("nfdump_falso.py")))
VENTANA = 1791682500                 # 2026-10-11 01:35 UTC = 2026-10-10 20:35 en Ecuador
AHORA = VENTANA + 3600
DIA = 20261010
MANANA_3AM = flujos_db.inicio_dia(20261011) + 3 * 3600   # el día 10 ya se puede cerrar
INV = {"routers": {
    "core-a": {"host": "192.0.2.1", "categorias": {"residencial": ["100.64.1.0/24"]}},
    "core-b": {"host": "192.0.2.2", "exportador": "192.0.2.102",
               "categorias": {"residencial": ["100.64.1.0/24"], "empresarial": ["100.64.2.0/24"]}}}}
BASE = emisor_netflow.lineas_csv(emisor_netflow.escenario_base())
FUERA = ["6,192.0.2.10,443,198.51.100.9,50000,...A....,1,500,1,1,2",   # tránsito: no es de ninguna categoría
         "6,198.51.100.9,50000,192.0.2.10,443,...A....,1,500,1,2,1"]
Uso = namedtuple("Uso", "total used free")


def https(abonado, puerto=5100):
    return f"6,{abonado},{puerto},192.0.2.10,443,...AP.S.,10,1000,1,7,1"


def uso_holgado(_ruta):
    return Uso(10 ** 12, 10 ** 11, 9 * 10 ** 11)


class UsoFalso:
    """Disco de 10 000 bytes: lo ocupado = fijo + lo que pesa data/nfcapd en este momento."""

    def __init__(self, datos, fijo, total=10_000):
        self.datos, self.fijo, self.total = datos, fijo, total

    def __call__(self, _ruta):
        usado = self.fijo + flujos_db.peso(self.datos / "nfcapd")
        return Uso(self.total, usado, self.total - usado)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.datos = Path(self.tmp.name)
        self.reloj = mock.patch.object(flujos_db, "_ahora", lambda: AHORA)
        self.reloj.start()
        self.cons = []

    def tearDown(self):
        self.reloj.stop()
        for c in self.cons:
            c.close()
        self.tmp.cleanup()

    def ahora(self, t):
        self.reloj.stop()
        self.reloj = mock.patch.object(flujos_db, "_ahora", lambda: t)
        self.reloj.start()

    def escribir(self, exportador, ventana, lineas, mtime=None):
        carpeta = self.datos / "nfcapd" / exportador.replace(".", "-")
        carpeta.mkdir(parents=True, exist_ok=True)
        ruta = carpeta / ("nfcapd." + time.strftime("%Y%m%d%H%M", time.gmtime(ventana)))
        ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")
        m = ventana + 60 if mtime is None else mtime
        os.utime(ruta, (m, m))
        return ruta

    def procesar(self, ahora=AHORA, **kw):
        kw.setdefault("uso", uso_holgado)
        return flujos.procesar(self.datos, kw.pop("inventario", INV), ahora=ahora, nfdump=FALSO, **kw)

    def con(self):
        c = flujos_db.abrir(self.datos / flujos_db.RUTA_RELATIVA)
        flujos_db.crear_esquema(c)
        self.cons.append(c)
        return c

    def contadores(self, con):
        """Todas las tablas de contadores, ordenadas: para comparar antes/después."""
        return {t: con.execute(f"SELECT * FROM {t} ORDER BY {', '.join(d[0])}").fetchall()
                for t, d in flujos_db.TABLAS_ARCHIVO.items()}

    def archivo(self, con, ruta):
        f = con.execute("SELECT estado, intentos, error, router, borrado FROM archivos WHERE ruta = ?", (ruta,)).fetchone()
        return dict(zip(("estado", "intentos", "error", "router", "borrado"), f)) if f else None


def todas_las_consultas(con, datos):
    return {
        "routers": flujos_db.routers_con_datos(con), "categorias": flujos_db.categorias_con_datos(con),
        "resumen": flujos_db.resumen(con, "residencial"), "por_hora": flujos_db.por_hora(con, "residencial"),
        "por_hora_30d": flujos_db.por_hora(con, "residencial", periodo="30d"),
        "top_destinos": flujos_db.top_destinos(con, "residencial", orden="abonados"),
        "top_puertos": flujos_db.top_puertos(con, "residencial", sentido="entrante", orden="bytes"),
        "top_puertos_30d": flujos_db.top_puertos(con, "residencial", periodo="30d"),
        "exactos": flujos_db.top_puertos_exactos(con, "residencial"),
        "consumidores": flujos_db.top_consumidores(con, "residencial", orden="total"),
        "percentiles": flujos_db.percentiles_abonado(con, "residencial"),
        "senales": flujos_db.senales(con, "residencial"),
        "servicios": flujos_db.servicios_categoria(con, "residencial", dias=14),
        "salud": flujos_db.salud(con, datos), "ventanas": flujos_db.ventanas_router(con, "core-a"),
        "interfaces": flujos_db.interfaces_router(con, "core-a"),
    }


class TestVacio(Base):
    def test_base_nueva_y_sin_esquema(self):
        for crear in (True, False):
            ruta = self.datos / f"b{crear}.db"
            con = flujos_db.abrir(ruta)
            self.cons.append(con)
            if crear:
                flujos_db.crear_esquema(con)
            r = todas_las_consultas(con, self.datos)
            json.dumps(r)
            for k in ("routers", "categorias", "por_hora", "por_hora_30d", "top_destinos", "top_puertos",
                      "top_puertos_30d", "exactos", "consumidores", "ventanas", "interfaces"):
                self.assertEqual(r[k], [], k)
            self.assertEqual(r["percentiles"], {})
            self.assertEqual((r["resumen"]["abonados_activos"], r["resumen"]["flujos"], r["resumen"]["routers"],
                              r["resumen"]["ultima_ventana"], r["resumen"]["relacion_bajada_subida"]),
                             (0, 0, [], None, None))
            self.assertEqual((r["resumen"]["desde"], r["resumen"]["hasta"]), ("2026-10-03", "2026-10-09"))
            self.assertEqual(r["senales"], {"sensibles": {}, "reflectores": {}, "barridos": [], "p2p": [],
                                            "dns": [], "destinos_no_publicos": []})
            self.assertEqual((r["servicios"]["filas"], r["servicios"]["abonados_total"]), ([], 0))
            self.assertEqual(r["salud"]["exportadores"], [])

    def test_solo_lectura_y_valores_invalidos(self):
        with self.assertRaises(FileNotFoundError):
            flujos_db.abrir(self.datos / "no-existe.db", solo_lectura=True)
        con = self.con()
        for llamada in (lambda: flujos_db.resumen(con, "residencial", periodo="x"),
                        lambda: flujos_db.top_puertos(con, "residencial", sentido="x"),
                        lambda: flujos_db.top_destinos(con, "residencial", orden="x"),
                        lambda: flujos_db.servicios_categoria(con, "residencial", dias=15)):
            with self.assertRaises(ValueError):
                llamada()


class TestProcesar(Base):
    def test_escenario_base_en_las_consultas(self):
        self.escribir("192.0.2.1", VENTANA, BASE + FUERA)
        r = self.procesar()
        self.assertEqual((r["procesados"], r["errores"], r["pendientes"]), (1, 0, 0))
        con = flujos_db.abrir(self.datos / flujos_db.RUTA_RELATIVA, solo_lectura=True)
        self.cons.append(con)
        res = flujos_db.resumen(con, "residencial", periodo="hoy")
        self.assertEqual((res["abonados_activos"], res["routers"], res["dias_con_datos"]), (8, ["core-a"], 1))
        self.assertEqual(res["ultima_ventana"], "2026-10-10T20:35:00-05:00")
        esc = emisor_netflow.escenario_base()
        subida = sum(f["bytes"] for f in esc if f["src"].startswith("100.64.1."))
        bajada = sum(f["bytes"] for f in esc if f["dst"].startswith("100.64.1."))
        self.assertEqual((res["bytes_subida"], res["bytes_bajada"]), (subida, bajada))
        self.assertEqual(res["relacion_bajada_subida"], round(bajada / subida, 1))
        salientes = {f["etiqueta"]: f for f in flujos_db.top_puertos(con, "residencial", periodo="hoy")}
        for etiqueta in ("tcp/443", "udp/443", "tcp/25", "tcp/23", "udp/53", "tcp/80", "udp/1024-49151"):
            self.assertEqual(salientes[etiqueta]["abonados"], 1, etiqueta)
        self.assertEqual(salientes["tcp/443"]["pct_abonados"], 12.5)
        self.assertEqual(salientes["tcp/443"]["servicio"], "HTTPS")
        entrantes = {f["etiqueta"] for f in flujos_db.top_puertos(con, "residencial", periodo="hoy", sentido="entrante")}
        self.assertEqual(entrantes, {"tcp/80", "udp/1900"})
        s = flujos_db.senales(con, "residencial", periodo="hoy")
        self.assertEqual([(b["abonado"], b["puerto"], b["remotos_max_ventana"]) for b in s["barridos"]],
                         [("100.64.1.14", "tcp/23", 60)])
        self.assertEqual([(p["abonado"], p["peers_udp_max"]) for p in s["p2p"]], [("100.64.1.16", 120)])
        self.assertIn("tcp/25 SMTP (envío directo)", s["sensibles"])
        self.assertIn("udp/1900 entrante (posible reflector)", s["reflectores"])
        self.assertEqual([(d["servidor"], d["abonados"]) for d in s["dns"]], [("192.0.2.53", 1)])
        self.assertIn("10.9.9.0/24", {d["red"] for d in s["destinos_no_publicos"]})
        p = flujos_db.percentiles_abonado(con, "residencial", periodo="hoy")
        self.assertEqual((p["tcp_nuevas"]["max"], p["syn"]["max"], p["peers_udp"]["max"]), (60, 60, 120))
        self.assertEqual(p["tcp_nuevas"]["n"], 6)
        top = flujos_db.top_consumidores(con, "residencial", periodo="hoy", orden="bajada")
        self.assertEqual(top[0]["abonado"], "100.64.1.15")  # 9000 + 150 bytes de bajada
        salud = flujos_db.salud(con, self.datos)
        [e] = salud["exportadores"]
        self.assertEqual((e["exportador"], e["router"], e["archivos"]), ("192.0.2.1", "core-a", 1))
        self.assertEqual(e["flujos"] - e["flujos_categoria"], 2)
        self.assertEqual(e["pct_fuera_categoria"], round(200 / len(BASE + FUERA), 1))
        [v] = flujos_db.ventanas_router(con, "core-a")
        self.assertEqual((v["estado"], v["flujos_categoria"]), ("ok", len(BASE)))
        itf = {(i["entrada"], i["salida"]) for i in flujos_db.interfaces_router(con, "core-a")}
        self.assertEqual(itf, {(7, 1), (1, 7)})
        horas = flujos_db.por_hora(con, "residencial", periodo="hoy")
        self.assertEqual(len(horas), 22)  # de 00:00 a 21:00 de hoy (son las 21:35), continuo
        self.assertEqual(sum(h["flujos"] for h in horas), len(BASE))
        json.dumps(todas_las_consultas(con, self.datos))

    def test_idempotente(self):
        ruta = self.escribir("192.0.2.1", VENTANA, BASE)
        self.procesar()
        con = self.con()
        antes = self.contadores(con)
        self.assertTrue(antes["servicio_dia"])
        self.assertEqual(self.procesar()["procesados"], 0)
        self.assertEqual(self.contadores(con), antes)
        # el mismo archivo crece después de procesado (RenameAppend): se avisa y no se suma
        with ruta.open("a", encoding="utf-8") as f:
            f.write(https("100.64.1.30") + "\n")
        os.utime(ruta, (VENTANA + 90, VENTANA + 90))
        self.assertEqual(self.procesar()["procesados"], 0)
        self.assertEqual(self.contadores(con), antes)
        self.assertIn("cambió", self.archivo(con, "192-0-2-1/nfcapd.202610110135")["error"])

    def test_archivo_a_medias(self):
        self.escribir("192.0.2.1", VENTANA, BASE[:10] + ["#ERROR"] + BASE[10:])
        con = self.con()
        vacio = self.contadores(con)
        for intento, estado in ((1, "reintentar"), (2, "reintentar"), (3, "error")):
            self.assertEqual(self.procesar()["errores"], 1)
            a = self.archivo(con, "192-0-2-1/nfcapd.202610110135")
            self.assertEqual((a["estado"], a["intentos"]), (estado, intento))
            self.assertEqual(self.contadores(con), vacio)  # ROLLBACK: ningún contador
        self.assertIn("truncado", a["error"])
        self.assertEqual(self.procesar()["errores"], 0)  # error es final: no se reintenta más

    def test_vigilante_mata_a_nfdump(self):
        self.escribir("192.0.2.1", VENTANA, BASE[:3] + ["#DORMIR 20"])
        with mock.patch.object(flujos, "LIMITE_NFDUMP", 1):
            inicio = time.monotonic()
            self.procesar()
        self.assertLess(time.monotonic() - inicio, 15)
        a = self.archivo(self.con(), "192-0-2-1/nfcapd.202610110135")
        self.assertEqual(a["estado"], "reintentar")
        self.assertIn("no terminó", a["error"])

    def test_proceso_muerto_no_bloquea_la_cola(self):
        # el archivo más viejo mata al procesador (SIGKILL por MemoryMax): no puede quedarse en cabeza para siempre
        self.escribir("192.0.2.1", VENTANA, BASE)
        self.escribir("192.0.2.1", VENTANA + 60, [https("100.64.1.18")])
        ruta = "192-0-2-1/nfcapd.202610110135"
        with mock.patch.object(flujos, "_leer_flujos", side_effect=SystemExit("muerte simulada")):
            for intento in (1, 2, 3):
                with self.assertRaises(SystemExit):
                    self.procesar()
                a = self.archivo(self.con(), ruta)
                self.assertEqual((a["estado"], a["intentos"], a["error"]), ("reintentar", intento, flujos.EN_CURSO))
        r = self.procesar()
        a = self.archivo(self.con(), ruta)
        self.assertEqual(a["estado"], "error")
        self.assertIn("abandonado tras 3 intentos", a["error"])
        self.assertEqual((r["procesados"], r["errores"]), (1, 1))  # el de detrás sí se procesa

    def test_excepcion_inesperada_queda_registrada_y_sigue(self):
        self.escribir("192.0.2.1", VENTANA, BASE)
        self.escribir("192.0.2.1", VENTANA + 60, [https("100.64.1.18")])
        original = flujos.Agregador.agregar

        def falla(ag, fl, obs):
            if ag.ventana == VENTANA:
                raise RuntimeError("dato raro")
            return original(ag, fl, obs)

        with mock.patch.object(flujos.Agregador, "agregar", falla):
            r = self.procesar()
        self.assertEqual((r["procesados"], r["errores"]), (1, 1))
        a = self.archivo(self.con(), "192-0-2-1/nfcapd.202610110135")
        self.assertEqual((a["estado"], a["intentos"]), ("reintentar", 1))
        self.assertIn("RuntimeError: dato raro", a["error"])

    def test_ip2asn_danado_no_tumba_el_procesador(self):
        texto = "".join(f"198.18.{i // 256}.{i % 256}\t198.18.{i // 256}.{i % 256}\t{64500 + i % 9}\tEC\tEJEMPLO\n"
                        for i in range(20000)).encode()
        bueno = gzip.compress(texto)
        danados = (bueno[:len(bueno) // 2],                                     # truncado: EOFError
                   bueno[:100] + bytes(400) + bueno[500:])                      # dañado: zlib.error / BadGzipFile
        for i, danado in enumerate(danados):
            tsv = self.datos / "ip2asn-v4.tsv.gz"
            tsv.write_bytes(danado)
            os.utime(tsv, (AHORA - 100 * (i + 1), AHORA - 100 * (i + 1)))
            for minuto in (0, 1):  # ni la primera ejecución ni las siguientes fallan
                self.escribir("192.0.2.1", VENTANA + 60 * (2 * i + minuto), [https(f"100.64.1.{20 + 2 * i + minuto}")])
                self.assertEqual(self.procesar()["procesados"], 1, (i, minuto))
            self.assertEqual(flujos_db.leer_meta(self.con(), "asn_malo"), str(int(tsv.stat().st_mtime)))

    def test_archivo_no_listo(self):
        reciente = AHORA - 60
        self.escribir("192.0.2.1", reciente, BASE, mtime=AHORA - 5)
        r = self.procesar()
        self.assertEqual(r["procesados"], 0)
        self.assertIsNone(self.archivo(self.con(), "192-0-2-1/" + "nfcapd." + time.strftime(
            "%Y%m%d%H%M", time.gmtime(reciente))))
        self.assertEqual(self.procesar(espera=False)["procesados"], 1)

    def test_vacio_y_actual_ignorado(self):
        self.escribir("192.0.2.1", VENTANA, FUERA)  # nada de abonados: el filtro lo deja todo fuera
        (self.datos / "nfcapd" / "192-0-2-1" / "nfcapd.current.123").write_text("x")
        (self.datos / "nfcapd" / "192-0-2-1" / ".nfstat").write_text("x")
        r = self.procesar()
        self.assertEqual((r["vacios"], r["procesados"]), (1, 0))
        self.assertEqual(self.contadores(self.con())["servicio_dia"], [])

    def test_exportador_desconocido(self):
        self.escribir("198.51.100.77", VENTANA, BASE)
        r = self.procesar()
        self.assertEqual(r["desconocidos"], 1)
        con = self.con()
        self.assertEqual(con.execute("SELECT ip, archivos, flujos FROM exportador_desconocido").fetchall(),
                         [("198.51.100.77", 1, len(BASE))])
        self.assertTrue(all(not v for v in self.contadores(con).values()))
        [e] = flujos_db.salud(con, self.datos)["exportadores"]
        self.assertEqual((e["exportador"], e["router"]), ("198.51.100.77", None))
        # su crudo se borra a la hora; el de un router conocido, a las CRUDO_HORAS
        self.procesar(ahora=VENTANA + 3700)
        self.assertFalse((self.datos / "nfcapd" / "198-51-100-77" / "nfcapd.202610110135").exists())

    def test_tope_de_memoria(self):
        self.escribir("192.0.2.1", VENTANA, BASE)
        self.procesar(tope_claves=50)
        con = self.con()
        a = self.archivo(con, "192-0-2-1/nfcapd.202610110135")
        self.assertEqual(a["estado"], "error")
        self.assertTrue(a["error"].startswith("demasiado grande"))
        self.assertTrue(all(not v for v in self.contadores(con).values()))

    def test_mismo_abonado_en_dos_routers(self):
        self.escribir("192.0.2.1", VENTANA, BASE)
        self.escribir("192.0.2.102", VENTANA, BASE)  # core-b exporta desde su IP de exportador
        self.escribir("192.0.2.2", VENTANA, BASE)    # host de core-b: no es su exportador -> desconocido
        r = self.procesar()
        self.assertEqual((r["procesados"], r["desconocidos"]), (2, 1))
        con = self.con()
        self.assertEqual(flujos_db.resumen(con, "residencial", periodo="hoy")["abonados_activos"], 16)
        self.assertEqual(flujos_db.resumen(con, "residencial", "core-b", periodo="hoy")["abonados_activos"], 8)
        https_ = [f for f in flujos_db.top_puertos(con, "residencial", periodo="hoy") if f["etiqueta"] == "tcp/443"]
        self.assertEqual((https_[0]["abonados"], https_[0]["pct_abonados"]), (2, 12.5))
        self.assertEqual(flujos_db.routers_con_datos(con), ["core-a", "core-b"])


class TestCierreDia(Base):
    def test_cierre_poda_foto_y_tardio(self):
        self.escribir("192.0.2.1", VENTANA, BASE)
        self.escribir("192.0.2.1", VENTANA + 60, [https("100.64.1.18")])
        self.assertEqual(self.procesar()["dias_cerrados"], [])
        con = self.con()
        self.assertEqual(con.execute("SELECT abonados, abonados_max_ventana FROM servicio_dia WHERE sentido = 0 "
                                     "AND proto = 6 AND puerto = 443").fetchone(), (None, 1))
        self.assertTrue(con.execute("SELECT 1 FROM puerto_dia WHERE puerto = 20001").fetchone())

        self.assertEqual(self.procesar(ahora=MANANA_3AM)["dias_cerrados"], ["2026-10-10"])
        self.assertEqual(con.execute("SELECT abonados FROM servicio_dia WHERE sentido = 0 AND proto = 6 "
                                     "AND puerto = 443").fetchone(), (2,))  # exacto: 2 abonados en 2 minutos
        # poda: los 119 puertos UDP altos sueltos (20001-20119) quedan en el cubo -1; 20000 es del rango RTP
        self.assertIsNone(con.execute("SELECT 1 FROM puerto_dia WHERE puerto BETWEEN 20001 AND 20119").fetchone())
        self.assertEqual(con.execute("SELECT flujos FROM puerto_dia WHERE proto = 17 AND puerto = -1").fetchone(),
                         (119,))
        self.assertTrue(con.execute("SELECT 1 FROM puerto_dia WHERE proto = 17 AND puerto = 20000").fetchone())
        self.assertEqual(con.execute("SELECT abonados, dias_con_datos FROM activos_7d WHERE hasta = ? "
                                     "AND router = '*'", (DIA,)).fetchone(), (9, 1))
        self.assertEqual(con.execute("SELECT abonados FROM servicio_7d WHERE hasta = ? AND router = '*' "
                                     "AND sentido = 0 AND proto = 6 AND puerto = 443", (DIA,)).fetchone(), (2,))
        self.ahora(MANANA_3AM)
        for periodo in ("ayer", "7d"):  # 7d sale de la foto; ayer, de la presencia
            [f] = [f for f in flujos_db.top_puertos(con, "residencial", periodo=periodo) if f["etiqueta"] == "tcp/443"]
            self.assertEqual((f["abonados"], f["pct_abonados"]), (2, 22.2), periodo)
        sc = flujos_db.servicios_categoria(con, "residencial")
        self.assertEqual((sc["abonados_total"], sc["dias_con_datos"], sc["desde"], sc["hasta"]),
                         (9, 1, "2026-10-04", "2026-10-10"))
        self.assertEqual(flujos_db.resumen(con, "residencial", periodo="30d")["abonados_modo"], "max_diario")

        # archivo tardío del día ya cerrado: marca el día sucio y se recalcula en la misma pasada
        self.escribir("192.0.2.1", VENTANA + 300, [https("100.64.1.19")])
        self.assertEqual(self.procesar(ahora=MANANA_3AM + 60)["dias_cerrados"], ["2026-10-10"])
        self.assertEqual(con.execute("SELECT abonados FROM servicio_dia WHERE sentido = 0 AND proto = 6 "
                                     "AND puerto = 443").fetchone(), (3,))
        self.assertEqual(con.execute("SELECT abonados FROM activos_7d WHERE hasta = ? AND router = '*'",
                                     (DIA,)).fetchone(), (10,))
        self.assertEqual(con.execute("SELECT sucio FROM dia_cierre WHERE dia = ?", (DIA,)).fetchone(), (0,))
        # repetir el cierre no cambia nada
        antes = self.contadores(con)
        flujos_db.cerrar_dia(con, DIA, MANANA_3AM + 120)
        self.assertEqual(self.contadores(con), antes)


class TestPercentiles(Base):
    def test_histograma_contra_calculo_directo(self):
        con = self.con()
        azar = random.Random(7)
        valores = [int(azar.lognormvariate(3, 1.6)) for _ in range(5003)]
        hist = {}
        for v in valores:
            hist[flujos_db.cubo(v)] = hist.get(flujos_db.cubo(v), 0) + 1
        con.executemany(flujos_db._UPSERT["hist_dia"], [(DIA, "core-a", "residencial", "syn", c, n)
                                                        for c, n in hist.items()])
        con.execute(flujos_db._UPSERT["abonado_dia"], (DIA, "core-a", "residencial", 1, 1, 1, 1, 1, 1,
                                                       0, 0, 0, 0, 0, 0, max(valores)))
        self.ahora(MANANA_3AM)
        p = flujos_db.percentiles_abonado(con, "residencial", periodo="ayer")["syn"]
        orden = sorted(valores)
        self.assertEqual((p["n"], p["max"]), (len(valores), max(valores)))
        for nombre, decimas in (("p50", 500), ("p90", 900), ("p99", 990), ("p99.9", 999)):
            exacto = orden[-(-decimas * len(orden) // 1000) - 1]
            self.assertGreaterEqual(p[nombre], exacto, nombre)       # nunca por debajo
            self.assertLessEqual(p[nombre], exacto * 1.1, nombre)    # error ≤ 10 %
        self.assertEqual([flujos_db.cubo(v) for v in (7, 99, 100, 1234, 56789)], [7, 99, 100, 1200, 56000])
        self.assertEqual([flujos_db.cota(c) for c in (7, 100, 1200, 56000)], [7, 109, 1299, 56999])


class TestRetencion(Base):
    def test_cada_tabla_borra_lo_que_dice(self):
        con = self.con()
        hoy = flujos_db.dia_de(AHORA)
        n = 0
        for tabla, (col, dias) in flujos_db.RETENCION.items():
            limite = flujos_db.sumar_dias(hoy, -dias) if col in ("dia", "hasta") else int(AHORA) - dias * 86400
            viejo = flujos_db.sumar_dias(limite, -1) if col in ("dia", "hasta") else limite - 1
            columnas = con.execute(f"PRAGMA table_info({tabla})").fetchall()
            for valor in (limite, viejo):
                fila = []
                for _, nombre, tipo, *_ in columnas:
                    n += 1
                    if nombre == col:
                        fila.append(valor)
                    elif nombre == "estado":
                        fila.append("ok")
                    elif nombre == "tipo":
                        fila.append("p2p")
                    else:
                        fila.append(f"x{n}" if tipo == "TEXT" else 1)
                con.execute(f"INSERT INTO {tabla} VALUES ({', '.join('?' * len(fila))})", fila)
        borradas = flujos_db.retencion(con, AHORA)
        for tabla, (col, _) in flujos_db.RETENCION.items():
            self.assertEqual(borradas[tabla], 1, tabla)
            self.assertEqual(con.execute(f"SELECT COUNT(*) FROM {tabla}").fetchone(), (1,), tabla)
        self.assertEqual(flujos_db.leer_meta(con, "ultima_retencion"), str(hoy))


class TestGuardian(Base):
    def crudo(self, con, ventana, estado=None, tam=100, exportador="192.0.2.1"):
        ruta = self.escribir(exportador, ventana, [])
        ruta.write_bytes(b"x" * tam)
        os.utime(ruta, (ventana + 60, ventana + 60))
        rel = f"{ruta.parent.name}/{ruta.name}"
        if estado:
            flujos_db.registrar_fallo(con, {"ruta": rel, "exportador": exportador, "router": "core-a",
                                            "ventana": ventana, "tam": tam, "mtime": ventana + 60, "estado": estado})
        return ruta

    def test_borra_procesado_viejo_y_restos(self):
        con = self.con()
        viejo = self.crudo(con, AHORA - 7 * 3600, "ok")
        reciente = self.crudo(con, AHORA - 3600, "ok")
        sin_procesar = self.crudo(con, AHORA - 8 * 3600)
        reintentar = self.crudo(con, AHORA - 9 * 3600, "reintentar")
        desconocido = self.crudo(con, AHORA - 2 * 3600, "desconocido", exportador="198.51.100.77")
        carpeta = viejo.parent
        vivo = carpeta / f"nfcapd.current.{os.getpid()}"
        muerto = carpeta / "nfcapd.current.4194999"
        for f in (vivo, muerto):
            f.write_text("x")
            os.utime(f, (AHORA - 3600, AHORA - 3600))
        g = flujos.guardian(self.datos, con, ahora=AHORA, uso=uso_holgado)
        self.assertEqual((g["borrados"], g["descartados"], g["estado"]), (2, 0, "ok"))
        self.assertEqual([p.exists() for p in (viejo, reciente, sin_procesar, reintentar, desconocido)],
                         [False, True, True, True, False])
        self.assertTrue(vivo.exists())       # pid vivo: es el archivo en curso del colector
        self.assertFalse(muerto.exists())    # resto de una caída
        self.assertIsNotNone(self.archivo(con, f"192-0-2-1/{viejo.name}")["borrado"])
        self.assertIsNone(self.archivo(con, f"192-0-2-1/{reciente.name}")["borrado"])

    def test_tope_de_tamano(self):
        con = self.con()
        rutas = [self.crudo(con, AHORA - (10 - i) * 600, "ok") for i in range(10)]  # 10 x 100 B = 1000 B
        g = flujos.guardian(self.datos, con, ahora=AHORA, uso=uso_holgado, limites={"crudo_max_gb": 500 / 1e9})
        self.assertEqual(g["borrados"], 6)  # hasta el 90 % de 500 B: quedan 4
        self.assertEqual([r.exists() for r in rutas], [False] * 6 + [True] * 4)

    def test_bajo_el_minimo_borra_procesados_recientes(self):
        con = self.con()
        procesados = [self.crudo(con, AHORA - 3000 + i * 60, "ok", tam=200) for i in range(5)]
        pendientes = [self.crudo(con, AHORA - 2000 + i * 60, tam=200) for i in range(5)]
        uso = UsoFalso(self.datos, fijo=6600)  # libre 1400 B = 14 % < 15 %: hay que llegar a 20 %
        g = flujos.guardian(self.datos, con, ahora=AHORA, uso=uso)
        self.assertEqual([p.exists() for p in procesados], [False, False, False, True, True])
        self.assertTrue(all(p.exists() for p in pendientes))
        self.assertEqual((g["descartados"], g["libre_pct"], g["estado"]), (0, 20.0, "ok"))

    def test_critico_descarta_sin_procesar(self):
        con = self.con()
        procesados = [self.crudo(con, AHORA - 3000 + i * 60, "ok") for i in range(5)]
        pendientes = [self.crudo(con, AHORA - 2000 + i * 60, tam=200) for i in range(5)]
        uso = UsoFalso(self.datos, fijo=8250)  # libre 2,5 %; sin procesados queda 7,5 % < 8 %
        g = flujos.guardian(self.datos, con, ahora=AHORA, uso=uso)
        self.assertFalse(any(p.exists() for p in procesados))
        self.assertEqual([p.exists() for p in pendientes], [False, False, True, True, True])
        self.assertEqual((g["descartados"], g["borrados"], g["libre_pct"], g["estado"]), (2, 7, 11.5, "aviso"))
        a = self.archivo(con, f"192-0-2-1/{pendientes[0].name}")
        self.assertEqual((a["estado"], a["error"]), ("descartado", "disco lleno"))
        self.assertIsNotNone(a["borrado"])
        self.assertEqual(flujos_db.leer_meta(con, "disco_critico"), "1")
        self.assertEqual(flujos_db.salud(con, self.datos)["descartados"], 2)
        # el procesador no vuelve a tomar los descartados
        self.assertEqual(self.procesar(espera=False)["vacios"], 3)


if __name__ == "__main__":
    unittest.main()
