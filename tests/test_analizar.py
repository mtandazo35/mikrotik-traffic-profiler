import gzip
import json
import tempfile
import unittest
from pathlib import Path

from mtp.analizar import analizar, limpiar, marca_desde, markdown, percentiles


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
        # DNS a un resolver externo, destino privado fuera de la categoría y 120 pares UDP (P2P)
        lineas.append(_linea("100.64.1.15:7000", "192.0.2.53:53", proto="udp"))
        lineas.append(_linea("100.64.1.15:7001", "10.9.9.9:80"))
        lineas += [_linea("100.64.1.16:51413", f"203.0.113.{i % 250}:{20000 + i}", proto="udp") for i in range(120)]
        with gzip.open(carpeta / "m1.txt.gz", "wt", encoding="utf-8") as f:
            f.write("\n".join(lineas))
        (carpeta / "muestras.jsonl").write_text(
            json.dumps({"ts": "20261010-203000", "cidr": "100.64.1.0/24", "archivo": "m1.txt.gz"}) + "\n"
            + json.dumps({"ts": "20261010-203100", "cidr": "100.64.2.0/24", "omitida": "demasiadas"}) + "\n",
            encoding="utf-8")

    def tearDown(self):
        self.tmp.cleanup()

    def test_perfil(self):
        p = analizar(self.datos, "residencial")
        self.assertEqual(p["resumen"]["muestras"], 1)
        self.assertEqual(p["resumen"]["horas_muestreadas"], ["20"])
        self.assertEqual(p["resumen"]["abonados_observados"], 7)
        self.assertIn(("udp", 53, "192.0.2.53"), {(f["proto"], f["puerto"], f["servidor"]) for f in p["dns"]})
        self.assertIn("10.9.9.0/24", {f["red"] for f in p["destinos_no_publicos"]})
        self.assertEqual([(f["abonado"], f["peers_udp"]) for f in p["p2p"]], [("100.64.1.16", 120)])
        self.assertEqual(p["por_abonado"]["peers_udp"]["max"], 120)
        self.assertIn("Posible P2P", markdown(p))
        claves = {(f["proto"], f["puerto"]) for f in p["salientes"]}
        self.assertTrue({("tcp", 443), ("udp", 443), ("tcp", 25), ("tcp", 23)} <= claves)
        self.assertEqual([(f["proto"], f["puerto"]) for f in p["entrantes"]], [("tcp", 80)])
        self.assertIn("tcp/25 SMTP (envío directo)", p["senales"])
        self.assertEqual(p["barridos"][0]["destinos_distintos"], 60)
        self.assertEqual(p["por_abonado"]["ips"]["max"], 120)  # el abonado P2P
        self.assertIn("Barrido", markdown(p))

    def test_ventana_y_retencion(self):
        # la muestra es del pasado: con ventana de 0 días no entra; limpiar a 0 días la borra
        self.assertEqual(analizar(self.datos, "residencial", dias=None)["resumen"]["muestras"], 1)
        self.assertEqual(analizar(self.datos, "residencial", dias=0)["resumen"]["muestras"], 0)
        carpeta = self.datos / "crudo" / "core-a" / "residencial"
        self.assertEqual(limpiar(self.datos, 0), 1)
        self.assertFalse((carpeta / "m1.txt.gz").exists())
        self.assertEqual((carpeta / "muestras.jsonl").read_text(encoding="utf-8"), "")

    def test_marca_desde(self):
        self.assertEqual(len(marca_desde(7)), 15)
        self.assertLess(marca_desde(7), marca_desde(1))

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
