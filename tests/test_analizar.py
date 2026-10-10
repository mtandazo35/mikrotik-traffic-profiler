import json
import tempfile
import unittest
from pathlib import Path

from mtp.analizar import analizar, markdown, percentiles


def _linea(src, dst, proto="tcp", estado="established", rsrc=None):
    rsrc = rsrc or dst
    return (f" 0  SAC  protocol={proto} src-address={src} dst-address={dst} reply-src-address={rsrc} "
            f"reply-dst-address=203.0.113.5:1 tcp-state={estado} orig-bytes=100 repl-bytes=900")


class TestAnalizar(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.datos = Path(self.tmp.name)
        carpeta = self.datos / "crudo" / "core-a" / "residencial"
        carpeta.mkdir(parents=True)
        lineas = [
            _linea("100.64.1.10:5000", "192.0.2.10:443"),
            _linea("100.64.1.11:5001", "192.0.2.10:443", proto="udp"),
            _linea("100.64.1.12:5002", "192.0.2.20:25"),
            _linea("198.51.100.4:4000", "203.0.113.5:8080", rsrc="100.64.1.13:80"),
        ]
        # 60 destinos distintos al 23 desde un solo abonado = barrido
        lineas += [_linea("100.64.1.14:6000", f"198.51.100.{i}:23", estado="syn-sent") for i in range(1, 61)]
        (carpeta / "m1.txt").write_text("\n".join(lineas), encoding="utf-8")
        (carpeta / "muestras.jsonl").write_text(
            json.dumps({"ts": "20261010-203000", "cidr": "100.64.1.0/24", "archivo": "m1.txt"}) + "\n"
            + json.dumps({"ts": "20261010-203100", "cidr": "100.64.2.0/24", "omitida": "demasiadas"}) + "\n",
            encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_perfil(self):
        p = analizar(self.datos, "residencial")
        self.assertEqual(p["resumen"]["muestras"], 1)
        self.assertEqual(p["resumen"]["horas_muestreadas"], ["20"])
        self.assertEqual(p["resumen"]["abonados_observados"], 5)
        claves = {(f["proto"], f["puerto"]) for f in p["salientes"]}
        self.assertTrue({("tcp", 443), ("udp", 443), ("tcp", 25), ("tcp", 23)} <= claves)
        self.assertEqual([(f["proto"], f["puerto"]) for f in p["entrantes"]], [("tcp", 80)])
        self.assertIn("tcp/25 SMTP (envío directo)", p["senales"])
        self.assertEqual(p["barridos"][0]["destinos_distintos"], 60)
        self.assertEqual(p["por_abonado"]["ips"]["max"], 60)
        self.assertIn("Barrido", markdown(p))

    def test_filtro_por_router(self):
        self.assertEqual(analizar(self.datos, "residencial", ["otro"])["resumen"]["muestras"], 0)


class TestPercentiles(unittest.TestCase):
    def test_rango_cercano(self):
        v = list(range(1, 101))
        p = percentiles(v)
        self.assertEqual((p["p50"], p["p90"], p["p99"], p["max"]), (50, 90, 99, 100))
        self.assertEqual(percentiles([7])["p99.9"], 7)
        self.assertEqual(percentiles([]), {})


if __name__ == "__main__":
    unittest.main()
