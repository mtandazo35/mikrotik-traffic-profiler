import json
import tempfile
import unittest
from pathlib import Path

from mtp import inventario

BASE = {"nombre": "core-centro", "host": "192.0.2.1", "puerto": "2222", "usuario": "trafico",
        "residencial": "100.64.0.0/22, 100.64.8.0/23", "empresarial": "", "exportador": "", "activo": "on"}


class TestFormulario(unittest.TestCase):
    def test_alta_valida(self):
        nombre, r = inventario.router_desde_form(BASE)
        self.assertEqual(nombre, "core-centro")
        self.assertEqual(r["puerto"], 2222)
        self.assertEqual(r["categorias"], {"residencial": ["100.64.0.0/22", "100.64.8.0/23"]})
        self.assertTrue(r["activo"])
        self.assertNotIn("exportador", r)

    def test_normaliza_rangos_y_exportador(self):
        _, r = inventario.router_desde_form({**BASE, "residencial": "100.64.1.7/24\n100.64.9.0/24",
                                             "exportador": "203.0.113.9", "activo": ""})
        self.assertEqual(r["categorias"]["residencial"], ["100.64.1.0/24", "100.64.9.0/24"])
        self.assertEqual(r["exportador"], "203.0.113.9")
        self.assertFalse(r["activo"])

    def test_rechazos(self):
        malos = [
            {"nombre": "Core Centro"}, {"nombre": ""}, {"host": "192.0.2.1; reboot"}, {"puerto": "70000"},
            {"puerto": "x"}, {"residencial": "", "empresarial": ""}, {"residencial": "100.64.0.0/33"},
            {"residencial": "10.0.0.0/4"}, {"residencial": "2001:db8::/48"}, {"exportador": "no-ip"},
            {"residencial": "100.64.0.0/22", "empresarial": "100.64.2.0/24"},  # solapados
            {"usuario": "a b"},
        ]
        for cambio in malos:
            with self.assertRaises(ValueError, msg=cambio):
                inventario.router_desde_form({**BASE, **cambio})


class TestGuardar(unittest.TestCase):
    def test_guardado_atomico_y_lectura(self):
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "inventario.json"
            self.assertEqual(inventario.leer(ruta)["routers"], {})
            inv = inventario.leer(ruta)
            inv["routers"]["a"] = {"host": "192.0.2.1"}
            inventario.guardar(ruta, inv)
            self.assertEqual(json.loads(ruta.read_text(encoding="utf-8"))["routers"]["a"]["host"], "192.0.2.1")
            self.assertEqual([p.name for p in Path(d).iterdir()], ["inventario.json"])  # sin temporales


if __name__ == "__main__":
    unittest.main()
