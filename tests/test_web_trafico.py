"""Páginas Tráfico y Firewall con un módulo de consultas falso (la forma exacta del contrato 5.3 de la spec)."""
import http.client
import json
import re
import sqlite3
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import quote, unquote, urlencode

from mtp import web

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


class Con:
    def __init__(self, registro):
        self.registro = registro

    def close(self):
        self.registro.append("close")


class FlujosFalso:
    """Mismos nombres que mtp.flujos_db; devuelve los ejemplos de la spec tal cual (más un ASN con <script>)."""
    RUTA_RELATIVA = "flujos.db"
    PERIODOS = ("hoy", "ayer", "7d", "30d")

    def __init__(self, existe=True, falla=None):
        self.existe, self.falla, self.llamadas = existe, falla, []

    def abrir(self, ruta, solo_lectura=False):
        self.llamadas.append(("abrir", Path(ruta).name, solo_lectura))
        if not self.existe:
            raise FileNotFoundError(ruta)
        return Con(self.llamadas)

    def routers_con_datos(self, con):
        return ["core-a"]

    def categorias_con_datos(self, con):
        return ["residencial"]

    def resumen(self, con, categoria, router=None, periodo="7d"):
        self.llamadas.append(("resumen", categoria, router, periodo))
        if self.falla:
            raise self.falla
        return {"categoria": categoria, "routers": ["core-a"], "periodo": periodo, "desde": "2026-10-03",
                "hasta": "2026-10-09", "dias_con_datos": 7, "abonados_activos": 4210, "abonados_modo": "exacto",
                "flujos": 123456789, "bytes_subida": 1100000000000, "bytes_bajada": 0, "relacion_bajada_subida": None,
                "ultima_ventana": "2026-10-10T20:35:00-05:00", "pendientes": 3}

    def por_hora(self, con, categoria, router=None, periodo="hoy"):
        return [{"inicio": "2026-10-10T19:00:00-05:00", "paso_segundos": 3600, "flujos": 40000,
                 "bytes_subida": 900000000, "bytes_bajada": 0, "abonados_max_ventana": 1500},
                {"inicio": "2026-10-10T20:00:00-05:00", "paso_segundos": 3600, "flujos": 51234,
                 "bytes_subida": 1200000000, "bytes_bajada": 9900000000, "abonados_max_ventana": 1830}]

    def top_destinos(self, con, categoria, router=None, periodo="7d", orden="bytes", limite=50):
        self.llamadas.append(("top_destinos", orden))
        return [{"asn": 15169, "nombre": "GOOGLE", "pais": "US", "abonados": 3900, "pct_abonados": 92.6,
                 "flujos": 912345, "bytes_subida": 120000000, "bytes_bajada": 2400000000, "bytes": 2520000000},
                {"asn": 64500, "nombre": "<script>alert(1)</script>", "pais": "EC", "abonados": 3, "pct_abonados": 0.1,
                 "flujos": 12, "bytes_subida": 100, "bytes_bajada": 200, "bytes": 300}]

    def top_puertos(self, con, categoria, router=None, periodo="7d", sentido="saliente", orden="abonados", limite=80):
        if sentido == "entrante":
            return [{"sentido": "entrante", "proto": "udp", "puerto": 1900, "puerto_hasta": 1900, "etiqueta": "udp/1900",
                     "servicio": "SSDP/UPnP", "abonados": 3, "pct_abonados": 0.1, "flujos": 40,
                     "bytes_subida": 1000, "bytes_bajada": 2000}]
        return [{"sentido": "saliente", "proto": "tcp", "puerto": 443, "puerto_hasta": 443, "etiqueta": "tcp/443",
                 "servicio": "HTTPS", "abonados": 4100, "pct_abonados": 97.4, "flujos": 50123456,
                 "bytes_subida": 900000000, "bytes_bajada": 8000000000}]

    def top_puertos_exactos(self, con, categoria, router=None, periodo="7d", limite=100):
        return [{"sentido": "saliente", "proto": "udp", "puerto": 27015, "servicio": "Steam / juegos Valve",
                 "flujos": 81234, "bytes": 51200000, "abonados_max_ventana": 37}]

    def top_consumidores(self, con, categoria, router=None, periodo="7d", orden="bajada", limite=50):
        self.llamadas.append(("top_consumidores", orden))
        return [{"router": "core-a", "abonado": "100.64.1.10", "bytes_subida": 3400000000, "bytes_bajada": 41000000000,
                 "flujos": 812345, "dias_activo": 7, "max_flujos": 640, "max_ips": 210, "max_peers_udp": 12}]

    def percentiles_abonado(self, con, categoria, router=None, periodo="7d"):
        return {"tcp_nuevas": {"p50": 3, "p90": 18, "p99": 79, "p99.9": 249, "max": 3120, "n": 5020331}}

    def senales(self, con, categoria, router=None, periodo="7d", limite=20):
        return {"sensibles": {"tcp/25 SMTP (envío directo)": [{"router": "core-a", "abonado": "100.64.1.12", "flujos": 4410,
                                                                "remotos_max_ventana": 38, "ventanas": 210,
                                                                "ultima": "2026-10-09T21:14:00-05:00"}]},
                "reflectores": {"udp/1900 entrante (posible reflector)": []},
                "barridos": [{"router": "core-a", "abonado": "100.64.1.14", "puerto": "tcp/23", "servicio": "Telnet",
                              "remotos_max_ventana": 60, "ventanas": 14, "ultima": "2026-10-09T03:02:00-05:00"}],
                "p2p": [{"router": "core-a", "abonado": "100.64.1.16", "peers_udp_max": 120, "ventanas": 300,
                         "ultima": "2026-10-09T22:40:00-05:00"}],
                "dns": [{"proto": "udp", "puerto": 53, "servidor": "192.0.2.53", "red": "AS64500 EJEMPLO (EC)",
                         "abonados": 900, "pct_abonados": 21.4, "flujos": 1203456}],
                "destinos_no_publicos": [{"red": "10.9.9.0/24", "abonados": 3, "flujos": 120, "bytes": 51000}]}

    def servicios_categoria(self, con, categoria, router=None, dias=7):
        self.llamadas.append(("servicios_categoria", categoria, router, dias))
        return {"categoria": categoria, "routers": ["core-a"], "desde": "2026-10-03", "hasta": "2026-10-09",
                "dias_con_datos": 7, "abonados_total": 4210,
                "filas": [{"sentido": "saliente", "proto": "tcp", "puerto": 25, "puerto_hasta": 25, "etiqueta": "tcp/25",
                           "servicio": "SMTP (envío directo)", "abonados": 12, "pct_abonados": 0.3, "flujos": 9120,
                           "bytes": 81200000, "dias_observado": 7},
                          {"sentido": "saliente", "proto": "tcp", "puerto": 443, "puerto_hasta": 443, "etiqueta": "tcp/443",
                           "servicio": "HTTPS", "abonados": 4100, "pct_abonados": 97.4, "flujos": 50123456,
                           "bytes": 8900000000, "dias_observado": 7}]}

    def salud(self, con, datos, horas=24):
        return {"exportadores": [{"exportador": "192.0.2.1", "router": "core-a", "ultimo_archivo": "2026-10-10T20:41:00-05:00",
                                  "archivos": 1440, "flujos": 40100000, "flujos_categoria": 39800000, "pct_fuera_categoria": 0.7,
                                  "secuencia_perdida": 0, "bytes_subida": 1100000000, "bytes_bajada": 0, "errores": 0},
                                 {"exportador": "198.51.100.77", "router": None, "ultimo_archivo": "2026-10-10T20:41:00-05:00",
                                  "archivos": 10, "flujos": 500, "flujos_categoria": 0, "pct_fuera_categoria": 100.0,
                                  "secuencia_perdida": 0, "bytes_subida": 0, "bytes_bajada": 0, "errores": 0}],
                "pendientes": 2, "en_error": 0, "descartados": 0, "ultima_ejecucion": "2026-10-10T20:43:20-05:00",
                "disco": {"total_bytes": 21000000000, "libre_bytes": 17500000000, "libre_pct": 83.3,
                          "crudo_bytes": 410000000, "db_bytes": 52000000, "estado": "ok"}}

    def ventanas_router(self, con, router, minutos=60):
        self.llamadas.append(("ventanas_router", router, minutos))
        return [{"ventana": "2026-10-10T20:40:00-05:00", "flujos_total": 28000, "flujos_categoria": 27900,
                 "bytes_subida": 18000000, "bytes_bajada": 0, "secuencia_perdida": 0, "estado": "ok"}]

    def interfaces_router(self, con, router, periodo="hoy"):
        return [{"entrada": 7, "salida": 1, "flujos": 3100000, "bytes": 2100000000}]


class FlujosVacio(FlujosFalso):
    """Base creada pero sin datos: listas vacías y ceros, como pide el contrato."""

    def routers_con_datos(self, con):
        return []

    def categorias_con_datos(self, con):
        return []

    def resumen(self, con, categoria, router=None, periodo="7d"):
        return {"categoria": categoria, "routers": [], "periodo": periodo, "desde": None, "hasta": None, "dias_con_datos": 0,
                "abonados_activos": 0, "abonados_modo": "exacto", "flujos": 0, "bytes_subida": 0, "bytes_bajada": 0,
                "relacion_bajada_subida": None, "ultima_ventana": None, "pendientes": 0}

    def _vacio(self, *a, **k):
        return []

    por_hora = top_destinos = top_puertos = top_puertos_exactos = top_consumidores = ventanas_router = interfaces_router = _vacio

    def percentiles_abonado(self, *a, **k):
        return {}

    def senales(self, *a, **k):
        return {"sensibles": {}, "reflectores": {}, "barridos": [], "p2p": [], "dns": [], "destinos_no_publicos": []}

    def servicios_categoria(self, con, categoria, router=None, dias=7):
        return {"categoria": categoria, "routers": [], "desde": None, "hasta": None, "dias_con_datos": 0,
                "abonados_total": 0, "filas": []}

    def salud(self, con, datos, horas=24):
        return {"exportadores": [], "pendientes": 0, "en_error": 0, "descartados": 0, "ultima_ejecucion": None,
                "disco": {"total_bytes": 0, "libre_bytes": 0, "libre_pct": 0.0, "crudo_bytes": 0, "db_bytes": 0, "estado": "ok"}}


class TestTraficoFirewall(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        (d / "inv.json").write_text(json.dumps({"routers": {"core-a": {"host": "192.0.2.1", "usuario": "trafico",
                                                                        "categorias": {"residencial": ["100.64.0.0/24"]}}}}))
        web.CFG.clear()
        web.CFG.update(usuario="admin", hash=web.hash_clave("clave-de-prueba-123", iteraciones=1000), secreto="x" * 32,
                       inventario=str(d / "inv.json"), datos=str(d / "data"), llave_publica="")
        cls.srv = ThreadingHTTPServer(("127.0.0.1", 0), web.Manejador)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.cookie = None

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.tmp.cleanup()
        web.FLUJOS = None

    def setUp(self):
        self.F = FlujosFalso()
        web.FLUJOS = self.F

    def _pedir(self, metodo, ruta, cuerpo=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1])
        cab = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            cab["Cookie"] = cookie
        c.request(metodo, ruta, urlencode(cuerpo) if cuerpo else None, cab)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read().decode()

    def _get(self, ruta):
        if not TestTraficoFirewall.cookie:
            _, cab, _ = self._pedir("POST", "/entrar", {"usuario": "admin", "clave": "clave-de-prueba-123"})
            TestTraficoFirewall.cookie = cab["Set-Cookie"].split(";")[0]
        return self._pedir("GET", ruta, cookie=TestTraficoFirewall.cookie)

    def test_sin_sesion_redirige(self):
        for ruta in ["/trafico", "/firewall", "/firewall/propuesta.rsc?categoria=residencial", "/trafico?periodo=7d"]:
            st, cab, cuerpo = self._pedir("GET", ruta)
            self.assertEqual((st, cab.get("Location")), (303, "/entrar"), ruta)
        self.assertEqual(self.F.llamadas, [])  # ni siquiera abre la base

    def test_trafico_con_datos(self):
        st, _, cuerpo = self._get("/trafico")
        self.assertEqual(st, 200)
        for texto in ("GOOGLE", "15169", "tcp/443", "HTTPS", "udp/1900", "100.64.1.10", "Steam / juegos Valve", "27015",
                      "tcp/25 SMTP (envío directo)", "192.0.2.53", "10.9.9.0/24", "<svg", "p99.9"):
            self.assertIn(texto, cuerpo, texto)
        self.assertIn("No llega la bajada", cuerpo)  # relacion_bajada_subida = None
        self.assertIn("Anotar esta IP en Routers", cuerpo)  # exportador desconocido (D4)
        self.assertIn("198.51.100.77", cuerpo)
        self.assertIn("4 210", cuerpo)  # abonados activos con separador de miles
        self.assertNotIn("Todavía no hay datos NetFlow", cuerpo)
        self.assertIn('href="/trafico" class="on"', cuerpo)
        self.assertIn(("abrir", "flujos.db", True), self.F.llamadas)
        self.assertIn(("resumen", "residencial", None, "hoy"), self.F.llamadas)  # periodo por defecto
        self.assertIn("close", self.F.llamadas)
        self.assertNotIn("Minuto a minuto", cuerpo)  # sin router elegido

    def test_trafico_con_router_y_ordenes(self):
        st, _, cuerpo = self._get("/trafico?router=core-a&periodo=7d&orden_destinos=abonados&orden_consumo=flujos")
        self.assertEqual(st, 200)
        self.assertIn("Minuto a minuto", cuerpo)
        self.assertIn("/interface print stats", cuerpo)
        self.assertIn(("resumen", "residencial", "core-a", "7d"), self.F.llamadas)
        self.assertIn(("ventanas_router", "core-a", 60), self.F.llamadas)
        self.assertIn(("top_destinos", "abonados"), self.F.llamadas)
        self.assertIn(("top_consumidores", "flujos"), self.F.llamadas)
        self.assertIn("<option value='core-a' selected>", cuerpo)

    def test_escapa_lo_que_viene_de_la_base(self):
        _, _, cuerpo = self._get("/trafico")
        self.assertNotIn("<script>alert(1)", cuerpo)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", cuerpo)

    def test_parametros_invalidos(self):
        malos = {"periodo": "<script>alert(2)</script>", "router": "../../<script>alert(3)</script>",
                 "categoria": "<script>alert(4)</script>", "orden_destinos": "x", "orden_consumo": "';drop"}
        st, _, cuerpo = self._get("/trafico?" + urlencode(malos))
        self.assertEqual(st, 200)
        for n in (2, 3, 4):
            self.assertNotIn(f"<script>alert({n})", cuerpo)
        self.assertIn("&lt;script&gt;alert(2)", cuerpo)  # el aviso (modal) lo muestra escapado
        self.assertIn("<dialog id=\"aviso\">", cuerpo)
        self.assertIn(("resumen", "residencial", None, "hoy"), self.F.llamadas)  # todo volvió al valor por defecto
        self.assertIn(("top_destinos", "bytes"), self.F.llamadas)
        st, _, cuerpo = self._get("/trafico?periodo=x")
        self.assertEqual(st, 200)
        self.assertIn("Periodo «x» desconocido", cuerpo)
        st, _, cuerpo = self._get("/firewall?dias=99&router=" + quote("../../"))
        self.assertEqual(st, 200)
        self.assertIn(("servicios_categoria", "residencial", None, 7), self.F.llamadas)
        self.assertIn("no válido (1 a 14)", cuerpo)

    def test_firewall_con_datos(self):
        st, _, cuerpo = self._get("/firewall?router=core-a&dias=7")
        self.assertEqual(st, 200)
        self.assertIn(("servicios_categoria", "residencial", "core-a", 7), self.F.llamadas)
        self.assertIn("Riesgo", cuerpo)
        self.assertIn("tcp/25", cuerpo)
        self.assertIn("Evidencia suficiente", cuerpo)
        self.assertIn("/firewall/propuesta.rsc?router=core-a&amp;categoria=residencial&amp;dias=7", cuerpo)
        self.assertIn("DET-RES-TCP25", cuerpo)  # vista previa de la propuesta
        self.assertIn("close", self.F.llamadas)

    def test_descarga_rsc(self):
        st, cab, cuerpo = self._get("/firewall/propuesta.rsc?categoria=residencial&dias=7")
        self.assertEqual(st, 200)
        self.assertEqual(cab["Content-Type"], "text/plain; charset=utf-8")
        self.assertEqual(cab["Content-Disposition"], 'attachment; filename="firewall-residencial.rsc"')
        self.assertIn("add chain=RES-SALIDA action=add-src-to-address-list address-list=DET-RES-TCP25", cuerpo)
        self.assertIn("action=drop protocol=tcp dst-port=25 disabled=yes", cuerpo)
        self.assertIn("dst-limit=498/1m,498,src-address/5m", cuerpo)
        self.assertIsNone(IPV4.search(cuerpo))

    def test_sin_base(self):
        web.FLUJOS = FlujosFalso(existe=False)
        for ruta in ("/trafico", "/firewall"):
            st, _, cuerpo = self._get(ruta)
            self.assertEqual(st, 200, ruta)
            self.assertIn("Todavía no hay datos NetFlow", cuerpo)
            self.assertIn('href="/#netflow"', cuerpo)
        st, _, cuerpo = self._get("/firewall/propuesta.rsc?categoria=residencial")
        self.assertEqual(st, 404)
        self.assertIn("Todavía no hay datos NetFlow", cuerpo)

    def test_modulo_no_instalado(self):
        web.FLUJOS = None
        real = web._flujos
        web._flujos = lambda: None  # como si mtp.flujos_db todavía no existiera
        try:
            st, _, cuerpo = self._get("/trafico")
        finally:
            web._flujos = real
        self.assertEqual(st, 200)
        self.assertIn("Todavía no hay datos NetFlow", cuerpo)

    def test_base_vacia(self):
        web.FLUJOS = FlujosVacio()
        st, _, cuerpo = self._get("/trafico?router=core-a")
        self.assertEqual(st, 200)
        self.assertIn("Todavía no hay datos NetFlow", cuerpo)
        self.assertIn("Sin datos en el periodo.", cuerpo)
        st, _, cuerpo = self._get("/firewall")
        self.assertEqual(st, 200)
        self.assertIn("Evidencia insuficiente", cuerpo)
        st, _, cuerpo = self._get("/firewall/propuesta.rsc")
        self.assertEqual(st, 200)
        self.assertIn("ATENCION: evidencia insuficiente", cuerpo)

    def test_error_de_base_controlado(self):
        web.FLUJOS = FlujosFalso(falla=sqlite3.OperationalError("database is locked <x>"))
        st, _, cuerpo = self._get("/trafico")
        self.assertEqual(st, 200)
        self.assertIn("No se pudo leer la base NetFlow", cuerpo)
        self.assertIn("&lt;x&gt;", cuerpo)
        self.assertIn("close", web.FLUJOS.llamadas)

    def test_navegacion(self):
        _, _, cuerpo = self._get("/doc")
        self.assertIn('href="/trafico"', cuerpo)
        self.assertIn('href="/firewall"', cuerpo)
        self.assertIn("NetFlow", cuerpo)
        self.assertIn("dst-limit", cuerpo)
        self.assertIn("solo <b>recibe</b> tráfico entrante (escaneos de internet) cuenta como", cuerpo)
        _, cab, _ = self._pedir("POST", "/accion", {"accion": "x"})
        self.assertEqual(unquote(cab.get("Location", "")), "/entrar")


if __name__ == "__main__":
    unittest.main()
