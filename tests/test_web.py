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

    def test_comandos_router(self):
        v7, v6, ver, quitar = web.comandos_router("ssh-rsa AAAAprueba mtp@x", "192.0.2.8")
        for bloque in (v7, v6):
            self.assertIn('contents="ssh-rsa AAAAprueba mtp@x"', bloque)
            self.assertIn("group=read address=192.0.2.8/32", bloque)
        self.assertIn("public-key-file=trafico.pub", v7)
        self.assertIn("public-key-file=trafico.txt", v6)
        self.assertNotIn("/file add", v6)  # no existe en RouterOS 6
        self.assertIn("/user remove [find name=trafico]", quitar)

    def test_comandos_netflow(self):
        buscar, activar, ver, quitar = web.comandos_netflow("192.0.2.8", 2055)
        self.assertIn("/ip traffic-flow target add dst-address=192.0.2.8 port=2055 version=9", activar)
        self.assertIn("interfaces=INTERFAZ-CLIENTES", activar)
        self.assertIn("enabled=yes", activar)
        self.assertIn("/ip traffic-flow target remove [find dst-address=192.0.2.8]", quitar)
        self.assertIn("/ip traffic-flow print", ver)
        # el script de búsqueda solo lee
        self.assertTrue(all(l.startswith("#") or " print" in l for l in buscar.splitlines()))

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
        self.assertIn("Conectar un router", cuerpo)
        self.assertIn("Exportar NetFlow", cuerpo)
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

    def _login(self):
        _, cab, _ = self._pedir("POST", "/entrar", {"usuario": "admin", "clave": "clave-de-prueba-123"})
        return cab["Set-Cookie"].split(";")[0]

    def test_routers_alta_edicion_pausa_borrado(self):
        cookie = self._login()
        inv = lambda: json.loads(Path(web.CFG["inventario"]).read_text(encoding="utf-8"))["routers"]  # noqa: E731
        form = {"nombre": "core-b", "host": "192.0.2.2", "puerto": "22", "usuario": "trafico",
                "residencial": "100.64.4.0/24", "empresarial": "", "exportador": "", "anterior": ""}
        _, cab, _ = self._pedir("POST", "/routers/guardar", form, cookie=cookie)
        self.assertIn("agregado", unquote(cab["Location"]))
        self.assertEqual(inv()["core-b"]["categorias"], {"residencial": ["100.64.4.0/24"]})
        self.assertFalse(inv()["core-b"]["activo"])
        _, cab, _ = self._pedir("POST", "/routers/guardar", form, cookie=cookie)
        self.assertIn("Ya existe", unquote(cab["Location"]))
        _, cab, _ = self._pedir("POST", "/routers/guardar", {**form, "residencial": "basura"}, cookie=cookie)
        self.assertIn("no es un rango válido", unquote(cab["Location"]))
        self._pedir("POST", "/routers/activo", {"nombre": "core-b", "activo": "on"}, cookie=cookie)
        self.assertTrue(inv()["core-b"]["activo"])
        _, cab, _ = self._pedir("POST", "/routers/guardar", {**form, "nombre": "core-c", "anterior": "core-b"}, cookie=cookie)
        self.assertIn("actualizado", unquote(cab["Location"]))
        self.assertNotIn("core-b", inv())
        st, _, cuerpo = self._pedir("GET", "/routers?editar=core-c", cookie=cookie)
        self.assertIn('value="192.0.2.2"', cuerpo)
        self._pedir("POST", "/routers/borrar", {"nombre": "core-c"}, cookie=cookie)
        self.assertNotIn("core-c", inv())
        self.assertIn("core-a", inv())  # el resto intacto

    def test_rechaza_otro_origen(self):
        cookie = self._login()
        c = http.client.HTTPConnection("127.0.0.1", self.srv.server_address[1])
        c.request("POST", "/routers/borrar", urlencode({"nombre": "core-a"}),
                  {"Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie, "Origin": "http://malo.example"})
        self.assertEqual(c.getresponse().status, 403)


if __name__ == "__main__":
    unittest.main()
