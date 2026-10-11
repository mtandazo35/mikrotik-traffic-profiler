"""Extremo a extremo con el nfcapd y el nfdump reales (Debian con el paquete nfdump). Sin ellos se salta.

nfcapd en una carpeta temporal y un puerto libre -> emisor v9 y v5 contra 127.0.0.1 -> procesar con el nfdump
real -> las consultas del panel deben dar las cifras del escenario base.
"""
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from mtp import flujos, flujos_db
from tests import emisor_netflow


def _puerto_libre():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipUnless(shutil.which("nfcapd") and shutil.which("nfdump"), "sin nfcapd/nfdump (apt install nfdump)")
class TestExtremoNetflow(unittest.TestCase):
    def test_v9_y_v5_hasta_las_consultas(self):
        with tempfile.TemporaryDirectory() as d:
            datos = Path(d)
            (datos / "nfcapd").mkdir()
            puerto = _puerto_libre()
            colector = subprocess.Popen(
                ["nfcapd", "-C", "none", "-4", "-M", str(datos / "nfcapd"), "-p", str(puerto), "-t", "2"],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env={**os.environ, "TZ": "UTC"})
            try:
                time.sleep(1.5)  # que abra el socket
                self.assertIsNone(colector.poll(), "nfcapd no arrancó")
                escenario = emisor_netflow.escenario_base()
                emisor_netflow.enviar("127.0.0.1", puerto, escenario, version=9)
                emisor_netflow.enviar("127.0.0.1", puerto, escenario, version=5)
                time.sleep(5)  # dos rotaciones de 2 s
            finally:
                colector.send_signal(signal.SIGTERM)  # cierra y renombra el archivo en curso
                try:
                    colector.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    colector.kill()
                    colector.wait()
                colector.stderr.close()
            self.assertTrue(list((datos / "nfcapd" / "127-0-0-1").glob("nfcapd.*")), "nfcapd no escribió nada")

            inv = {"routers": {"core-e2e": {"host": "192.0.2.1", "exportador": "127.0.0.1",
                                            "categorias": {"residencial": ["100.64.1.0/24"]}}}}
            r = flujos.procesar(datos, inv, espera=False)
            self.assertEqual((r["errores"], r["desconocidos"]), (0, 0), r)
            self.assertGreaterEqual(r["procesados"], 1, r)

            con = flujos_db.abrir(datos / flujos_db.RUTA_RELATIVA, solo_lectura=True)
            try:
                [e] = flujos_db.salud(con, datos)["exportadores"]
                self.assertEqual((e["exportador"], e["router"]), ("127.0.0.1", "core-e2e"))
                self.assertEqual(e["flujos_categoria"], 2 * len(escenario))  # v9 y v5: todo decodificado
                self.assertEqual(e["pct_fuera_categoria"], 0.0)
                res = flujos_db.resumen(con, "residencial", periodo="hoy")
                self.assertEqual(res["abonados_activos"], 8)
                salientes = {f["etiqueta"]: f["abonados"] for f in flujos_db.top_puertos(con, "residencial",
                                                                                         periodo="hoy")}
                for etiqueta in ("tcp/443", "udp/443", "tcp/25", "tcp/23", "udp/53", "tcp/80"):
                    self.assertEqual(salientes.get(etiqueta), 1, etiqueta)
                entrantes = {f["etiqueta"] for f in flujos_db.top_puertos(con, "residencial", periodo="hoy",
                                                                          sentido="entrante")}
                self.assertEqual(entrantes, {"tcp/80", "udp/1900"})
                s = flujos_db.senales(con, "residencial", periodo="hoy")
                self.assertEqual([(b["abonado"], b["puerto"], b["remotos_max_ventana"]) for b in s["barridos"]],
                                 [("100.64.1.14", "tcp/23", 60)])
                self.assertEqual([(p["abonado"], p["peers_udp_max"]) for p in s["p2p"]], [("100.64.1.16", 120)])
                self.assertEqual([(x["servidor"], x["abonados"]) for x in s["dns"]], [("192.0.2.53", 1)])
                self.assertIn("tcp/25 SMTP (envío directo)", s["sensibles"])
                p = flujos_db.percentiles_abonado(con, "residencial", periodo="hoy")
                self.assertIn(p["syn"]["max"], (60, 120))  # 120 si v9 y v5 cayeron en el mismo archivo
            finally:
                con.close()


if __name__ == "__main__":
    unittest.main()
