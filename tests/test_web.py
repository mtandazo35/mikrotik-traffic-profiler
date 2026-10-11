import http.client
import json
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlencode

from mtp import web


class TestCredenciales(unittest.TestCase):
    def test_hash_y_verificacion(self):
        h = web.hash_clave("una-clave-larga", iteraciones=1000)
        self.assertTrue(web.verificar_clave("una-clave-larga", h))
        self.assertFalse(web.verificar_clave("otra", h))
        self.assertFalse(web.verificar_clave("x", "basura"))

    def test_sesion_firmada_y_caducidad(self):
        t = web.firmar("admin", "s3creto", ahora=1000)
        self.assertEqual(web.sesion_valida(t, "s3creto", ahora=1001), "admin")
        self.assertIsNone(web.sesion_valida(t, "otro", ahora=1001))
        self.assertIsNone(web.sesion_valida(t, "s3creto", ahora=1000 + 9 * 3600))
        self.assertIsNone(web.sesion_valida(t.replace("admin", "root"), "s3creto", ahora=1001))

    def test_archivo_seguro(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.json").write_text("{}")
            self.assertIsNotNone(web.archivo_seguro(d, "a.json"))
            for malo in ["../a.json", "..", "/etc/passwd", "", None, ".oculto", "no.json"]:
                self.assertIsNone(web.archivo_seguro(d, malo), malo)


class TestServidor(unittest.TestCase):
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

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.tmp.cleanup()

    def _pedir(self, metodo, ruta, cuerpo=None, cookie=None):
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1])
        cab = {"Content-Type": "application/x-www-form-urlencoded"}
        if cookie:
            cab["Cookie"] = cookie
        c.request(metodo, ruta, urlencode(cuerpo) if cuerpo else None, cab)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read().decode()

    def test_sin_sesion_redirige(self):
        for ruta in ["/", "/muestras", "/informes", "/doc", "/tarea?f=x.log"]:
            st, cab, _ = self._pedir("GET", ruta)
            self.assertEqual((st, cab.get("Location")), (303, "/entrar"), ruta)
        st, cab, _ = self._pedir("POST", "/accion", {"accion": "descubrir", "router": "core-a"})
        self.assertEqual(cab.get("Location"), "/entrar")

    def test_login_y_panel(self):
        st, _, _ = self._pedir("POST", "/entrar", {"usuario": "admin", "clave": "mala"})
        self.assertEqual(st, 401)
        st, cab, _ = self._pedir("POST", "/entrar", {"usuario": "admin", "clave": "clave-de-prueba-123"})
        self.assertEqual(st, 303)
        cookie = cab["Set-Cookie"].split(";")[0]
        self.assertIn("HttpOnly", cab["Set-Cookie"])
        st, _, cuerpo = self._pedir("GET", "/", cookie=cookie)
        self.assertEqual(st, 200)
        self.assertIn("core-a", cuerpo)
        st, _, cuerpo = self._pedir("GET", "/doc", cookie=cookie)
        self.assertIn("Documentación", cuerpo)
        st, cab, _ = self._pedir("POST", "/accion", {"accion": "set", "router": "core-a"}, cookie=cookie)
        self.assertIn("Acción desconocida", unquote(cab["Location"]))
        st, cab, _ = self._pedir("POST", "/accion", {"accion": "recolectar", "router": "otro", "categoria": "residencial"},
                                 cookie=cookie)
        self.assertIn("no está en el inventario", unquote(cab["Location"]))
        st, cab, _ = self._pedir("POST", "/accion", {"accion": "contar", "router": "core-a", "categoria": "empresarial"},
                                 cookie=cookie)
        self.assertIn("categoría no existe", unquote(cab["Location"]))
        st, _, _ = self._pedir("GET", "/tarea?f=../../inv.json", cookie=cookie)
        self.assertEqual(st, 404)


if __name__ == "__main__":
    unittest.main()
