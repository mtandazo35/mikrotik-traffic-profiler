import contextlib
import io
import re
import tempfile
import types
import unittest
from pathlib import Path

from mtp import firewall, servicios

IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")


def _fila(sentido, proto, puerto, abonados, hasta=None, total=10000, flujos=100):
    hasta = puerto if hasta is None else hasta
    return {"sentido": sentido, "proto": proto, "puerto": puerto, "puerto_hasta": hasta,
            "etiqueta": firewall.etiqueta(proto, puerto, hasta), "servicio": servicios.nombre(proto, puerto),
            "abonados": abonados, "pct_abonados": round(abonados * 100 / total, 1), "flujos": flujos,
            "bytes": flujos * 1000, "dias_observado": 7}


def _servicios(filas, total=10000, dias=7, categoria="residencial"):
    return {"categoria": categoria, "routers": ["core-a"], "desde": "2026-10-03", "hasta": "2026-10-09",
            "dias_con_datos": dias, "abonados_total": total, "filas": filas}


def _clase(cl, sentido, etiqueta):
    filas = [f for f in cl["filas"] if f["sentido"] == sentido and f["etiqueta"] == etiqueta]
    assert len(filas) == 1, (sentido, etiqueta, filas)
    return filas[0]


PERC = {"tcp_nuevas": {"p50": 3, "p90": 18, "p99": 79, "p99.9": 249, "max": 3120, "n": 5020331}}


class TestClasificar(unittest.TestCase):
    def test_umbrales_en_su_borde(self):
        # sobre 10 000 abonados: 500 = 5,0 %, 490 = 4,9 %, 50 = 0,5 %, 49 = 0,49 % (A lo informa redondeado: 0.5)
        cl = firewall.clasificar(_servicios([
            _fila("saliente", "tcp", 8080, 500), _fila("saliente", "tcp", 8443, 490),
            _fila("saliente", "tcp", 1935, 50), _fila("saliente", "tcp", 5222, 49)]))
        self.assertEqual(_clase(cl, "saliente", "tcp/8080")["clase"], "esencial")
        self.assertEqual(_clase(cl, "saliente", "tcp/8443")["clase"], "usado")
        self.assertEqual(_clase(cl, "saliente", "tcp/1935")["clase"], "usado")
        f = _clase(cl, "saliente", "tcp/5222")
        self.assertEqual(f["pct_abonados"], 0.5)  # lo que llega redondeado…
        self.assertEqual(f["clase"], "minoritario")  # …no engaña: se decide con los conteos
        self.assertIn("0.49", f["motivo"])

    def test_umbrales_con_pct_sin_total(self):
        filas = [_fila("saliente", "tcp", 8080, 0), _fila("saliente", "tcp", 8443, 0)]
        filas[0]["pct_abonados"], filas[1]["pct_abonados"] = 5.0, 0.49
        cl = firewall.clasificar(_servicios(filas, total=0))
        self.assertEqual(_clase(cl, "saliente", "tcp/8080")["clase"], "esencial")
        self.assertEqual(_clase(cl, "saliente", "tcp/8443")["clase"], "minoritario")

    def test_riesgo_y_revisar(self):
        cl = firewall.clasificar(_servicios([
            _fila("saliente", "tcp", 25, 12), _fila("saliente", "tcp", 445, 500),
            _fila("entrante", "udp", 1900, 3), _fila("saliente", "tcp", 16464, 2, hasta=16471),
            _fila("entrante", "udp", 53, 900)]))
        smtp = _clase(cl, "saliente", "tcp/25")
        self.assertEqual((smtp["clase"], smtp["revisar"]), ("riesgo", False))
        smb = _clase(cl, "saliente", "tcp/445")
        self.assertEqual((smb["clase"], smb["revisar"]), ("riesgo", True))  # 5 %: masivo, decidir a mano
        self.assertEqual(_clase(cl, "entrante", "udp/1900")["clase"], "riesgo")
        self.assertEqual(_clase(cl, "saliente", "tcp/16464-16471")["clase"], "riesgo")
        # udp/53 entrante es reflector aunque udp/53 saliente esté en «nunca bloquear»
        self.assertEqual(_clase(cl, "entrante", "udp/53")["clase"], "riesgo")
        self.assertEqual(cl["conteo"]["riesgo"], 5)

    def test_nunca_bloquear_gana_al_porcentaje(self):
        cl = firewall.clasificar(_servicios([
            _fila("saliente", "tcp", 443, 1), _fila("saliente", "tcp", 853, 2), _fila("saliente", "gre", 0, 1),
            _fila("saliente", "udp", 3478, 1, hasta=3481)]))
        for et in ("tcp/443", "tcp/853", "gre", "udp/3478-3481"):
            self.assertEqual(_clase(cl, "saliente", et)["clase"], "esencial", et)
        self.assertIn("política DNS", _clase(cl, "saliente", "tcp/853")["motivo"])

    def test_rangos_anchos_y_cubos_no_son_riesgo(self):
        # udp/10000-20000 (RTP) contiene udp/11211 pero no es un reflector; el cubo tcp/1024-49151 contiene 2323
        cubo = {**_fila("saliente", "tcp", -1, 600, hasta=49151), "etiqueta": "tcp/1024-49151"}
        cl = firewall.clasificar(_servicios([_fila("entrante", "udp", 10000, 10, hasta=20000), cubo]))
        self.assertEqual(_clase(cl, "entrante", "udp/10000-20000")["clase"], "minoritario")
        self.assertEqual(_clase(cl, "saliente", "tcp/1024-49151")["clase"], "esencial")

    def test_no_observado(self):
        cl = firewall.clasificar(_servicios([_fila("saliente", "tcp", 25, 12)]))
        telnet = _clase(cl, "saliente", "tcp/23")
        self.assertEqual((telnet["clase"], telnet["riesgo"], telnet["abonados"]), ("no_observado", True, 0))
        self.assertEqual(_clase(cl, "entrante", "tcp/3389")["clase"], "no_observado")
        ssh = _clase(cl, "saliente", "tcp/22")  # del catálogo, no de riesgo
        self.assertEqual((ssh["clase"], ssh["riesgo"]), ("no_observado", False))
        self.assertEqual(_clase(cl, "saliente", "tcp/25")["clase"], "riesgo")  # observado: sin fila duplicada
        self.assertEqual(_clase(cl, "saliente", "tcp/16464-16471")["clase"], "no_observado")

    def test_rango_ancho_observado_no_tapa_riesgo_no_observado(self):
        # ver udp/10000-20000 (RTP) y udp/5000-5500 entrantes no prueba que haya memcached (11211) ni mDNS (5353)
        cl = firewall.clasificar(_servicios([_fila("entrante", "udp", 10000, 10, hasta=20000),
                                             _fila("entrante", "udp", 5000, 10, hasta=5500)]), PERC)
        for et in ("udp/11211", "udp/5353"):
            f = _clase(cl, "entrante", et)
            self.assertEqual((f["clase"], f["riesgo"]), ("no_observado", True), et)
        rsc = firewall.propuesta_rsc(cl, PERC)
        self.assertIn("# add chain=RES-ENTRADA action=add-dst-to-address-list address-list=DET-RES-ENT-UDP11211 ", rsc)
        self.assertIn("# add chain=RES-ENTRADA action=add-dst-to-address-list address-list=DET-RES-ENT-UDP5353 ", rsc)
        # y una fila exacta sí cuenta como observada (sin duplicado no_observado)
        cl = firewall.clasificar(_servicios([_fila("entrante", "udp", 11211, 1)]))
        self.assertEqual(_clase(cl, "entrante", "udp/11211")["clase"], "riesgo")

    def test_evidencia_suficiente(self):
        self.assertTrue(firewall.clasificar(_servicios([], total=50, dias=7))["suficiente"])
        pocos_dias = firewall.clasificar(_servicios([], total=4210, dias=6))
        self.assertFalse(pocos_dias["suficiente"])
        self.assertIn("6 días", pocos_dias["motivo_insuficiente"])
        pocos = firewall.clasificar(_servicios([], total=49, dias=7))
        self.assertFalse(pocos["suficiente"])
        self.assertIn("49 abonados", pocos["motivo_insuficiente"])

    def test_no_modifica_la_entrada(self):
        entrada = _servicios([_fila("saliente", "tcp", 25, 12)])
        firewall.clasificar(entrada)
        self.assertNotIn("clase", entrada["filas"][0])
        self.assertEqual(len(entrada["filas"]), 1)


class TestPropuesta(unittest.TestCase):
    def setUp(self):
        self.cl = firewall.clasificar(_servicios([
            _fila("saliente", "tcp", 25, 12), _fila("saliente", "tcp", 445, 600), _fila("entrante", "udp", 1900, 3),
            _fila("saliente", "tcp", 16464, 2, hasta=16471), _fila("saliente", "tcp", 443, 9800)]), PERC)
        self.rsc = firewall.propuesta_rsc(self.cl, PERC, fecha="2026-10-10")
        self.reglas = [l for l in self.rsc.splitlines() if l.startswith("add ")]

    def test_pareja_deteccion_y_drop_por_riesgo_observado(self):
        self.assertIn("add chain=RES-SALIDA action=add-src-to-address-list address-list=DET-RES-TCP25 "
                      "address-list-timeout=1d protocol=tcp dst-port=25 comment=", self.rsc)
        self.assertIn("add chain=RES-SALIDA action=drop protocol=tcp dst-port=25 disabled=yes", self.rsc)
        self.assertIn("add chain=RES-ENTRADA action=add-dst-to-address-list address-list=DET-RES-ENT-UDP1900", self.rsc)
        self.assertIn("add chain=RES-ENTRADA action=drop protocol=udp dst-port=1900 disabled=yes", self.rsc)
        self.assertIn("address-list=DET-RES-TCP16464-16471 address-list-timeout=1d protocol=tcp dst-port=16464-16471", self.rsc)
        # la evidencia va en el comentario de la regla
        self.assertRegex(self.rsc, r'DET-RES-TCP25 .*comment="RES: .*evidencia: 12 abonados, 0\.12 %, 100 flujos, 7 d\)"')

    def test_masivo_y_no_observado_solo_comentados(self):
        for l in self.rsc.splitlines():
            if "dst-port=445" in l or "dst-port=23 " in l or "dst-port=3389" in l:
                self.assertTrue(l.startswith("#"), l)
        self.assertIn("# masivo: decidir a mano - tcp/445", self.rsc)
        self.assertIn("Bloqueo preventivo opcional (saliente", self.rsc)
        self.assertIn("# add chain=RES-SALIDA action=add-src-to-address-list address-list=DET-RES-TCP23 ", self.rsc)

    def test_todo_en_deteccion_y_solo_conexiones_nuevas(self):
        drops = [l for l in self.reglas if "action=drop" in l]
        self.assertGreaterEqual(len(drops), 4)
        for l in drops:
            self.assertIn("disabled=yes", l)
        for l in self.reglas:
            if l.startswith("add chain=forward"):
                self.assertIn("connection-state=new", l)
                self.assertIn("action=jump", l)
        self.assertNotIn("action=accept protocol", self.rsc)
        self.assertIn('# Rollback: /ip firewall filter remove [find comment~"^RES:"]', self.rsc)

    def test_sintaxis_plausible_y_sin_ips(self):
        self.assertIsNone(IPV4.search(self.rsc), IPV4.search(self.rsc))
        for l in self.rsc.splitlines():
            self.assertTrue(l.startswith(("#", "/ip firewall ", "add chain=")), l)
            if l.startswith("add "):
                self.assertEqual(l.count('"') % 2, 0, l)
                self.assertRegex(l, r'comment="[ -~]*"$')  # comentario ASCII imprimible, al final
                self.assertNotIn("$", l)
        self.assertEqual(self.rsc.splitlines().count("/ip firewall filter"), 1)
        self.assertIn("# add list=CAT-RESIDENCIAL address=<rango residencial>", self.rsc)

    def test_archivo_completo_en_ascii(self):
        # /import de RouterOS 6.49 puede fallar con UTF-8: ni la cabecera lleva acentos, rayas ni flechas
        insuficiente = firewall.clasificar(_servicios([_fila("saliente", "tcp", 445, 600), _fila("saliente", "tcp", 25, 1)],
                                                      total=49, dias=6), PERC)
        for texto in (self.rsc, firewall.propuesta_rsc(insuficiente, PERC, fecha="2026-10-10", limite_conexiones=300),
                      firewall.propuesta_rsc(firewall.clasificar(_servicios([], categoria="categoría")), {})):
            texto.encode("ascii")  # UnicodeEncodeError si queda algo fuera de ASCII
            self.assertTrue(all(c == "\n" or " " <= c <= "~" for c in texto))
        self.assertIn("Despliegue: respaldo (/system backup save + /export) -> Safe Mode -> UN core canario", self.rsc)
        self.assertIn("# Propuesta firewall residencial - mikrotik-traffic-profiler (NetFlow)", self.rsc)
        self.assertIn("C2 Meris", self.rsc)

    def test_dst_limit_es_dos_veces_p999_hacia_arriba(self):
        self.assertIn("dst-limit=498/1m,498,src-address/5m", self.rsc)
        impar = {"tcp_nuevas": {"p99.9": 249.5}}
        self.assertIn("dst-limit=499/1m,499,src-address/5m", firewall.propuesta_rsc(self.cl, impar))
        sin = firewall.propuesta_rsc(self.cl, {})
        self.assertNotIn("dst-limit", sin.replace("# Sin percentiles NetFlow de tcp_nuevas: no se propone limite de rafaga (dst-limit).", ""))

    def test_limite_de_conexiones_opcional(self):
        self.assertNotIn("connection-limit=", self.rsc)
        con = firewall.propuesta_rsc(self.cl, PERC, limite_conexiones=300)
        self.assertIn("action=add-src-to-address-list address-list=DET-RES-CONEX address-list-timeout=1d protocol=tcp "
                      "connection-limit=300,32", con)
        self.assertIn("action=drop protocol=tcp connection-limit=300,32 disabled=yes", con)

    def test_determinista_y_fecha(self):
        self.assertEqual(self.rsc, firewall.propuesta_rsc(self.cl, PERC, fecha="2026-10-10"))
        self.assertIn("# Generada: 2026-10-10", self.rsc)
        self.assertNotIn("Generada", firewall.propuesta_rsc(self.cl, PERC))
        self.assertIn("# Evidencia: core-a, 2026-10-03..2026-10-09 (7 dias), 10000 abonados activos.", self.rsc)

    def test_prefijo_y_lista_por_categoria(self):
        emp = firewall.propuesta_rsc(firewall.clasificar(_servicios([_fila("saliente", "tcp", 25, 12)],
                                                                    categoria="empresarial")), PERC)
        self.assertIn("jump-target=EMP-SALIDA src-address-list=CAT-EMPRESARIAL", emp)
        self.assertIn("DET-EMP-TCP25", emp)
        otra = firewall.propuesta_rsc(firewall.clasificar(_servicios([], categoria="pymes")), PERC, lista="mi lista!")
        self.assertIn("jump-target=PYMES-SALIDA src-address-list=MILISTA", otra)

    def test_insuficiente_lo_advierte(self):
        cl = firewall.clasificar(_servicios([_fila("saliente", "tcp", 25, 12)], total=49, dias=6), PERC)
        self.assertIn("# ATENCION: evidencia insuficiente", firewall.propuesta_rsc(cl, PERC))
        self.assertNotIn("ATENCION", self.rsc)


class TestMain(unittest.TestCase):
    def _db(self, servicios_cat, existe=True):
        llamadas = []

        class Con:
            def close(self):
                llamadas.append("close")

        def abrir(ruta, solo_lectura=False):
            llamadas.append(("abrir", Path(ruta).name, solo_lectura))
            if not existe:
                raise FileNotFoundError(ruta)
            return Con()

        def servicios_categoria(con, categoria, router=None, dias=7):
            llamadas.append(("servicios", categoria, router, dias))
            return servicios_cat

        db = types.SimpleNamespace(RUTA_RELATIVA="flujos.db", abrir=abrir, servicios_categoria=servicios_categoria,
                                   percentiles_abonado=lambda con, categoria, router=None, periodo="7d": PERC)
        return db, llamadas

    def _main(self, argv, db):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            rc = firewall.main(argv, db=db)
        return rc, err.getvalue()

    def test_insuficiente_sale_1_salvo_forzar(self):
        db, llamadas = self._db(_servicios([_fila("saliente", "tcp", 25, 12)], total=49, dias=6))
        with tempfile.TemporaryDirectory() as d:
            salida = Path(d) / "p.rsc"
            rc, err = self._main(["--datos", d, "--categoria", "residencial", "--salida", str(salida)], db)
            self.assertEqual(rc, 1)
            self.assertIn("evidencia insuficiente", err)
            self.assertFalse(salida.exists())
            rc, _ = self._main(["--datos", d, "--categoria", "residencial", "--salida", str(salida), "--forzar",
                                "--fecha", "2026-10-10"], db)
            self.assertEqual(rc, 0)
            texto = salida.read_text(encoding="utf-8")
            self.assertIn("ATENCION: evidencia insuficiente", texto)
            self.assertIn("DET-RES-TCP25", texto)
        self.assertIn(("abrir", "flujos.db", True), llamadas)
        self.assertIn("close", llamadas)

    def test_suficiente_y_parametros(self):
        db, llamadas = self._db(_servicios([_fila("saliente", "tcp", 25, 12)]))
        with tempfile.TemporaryDirectory() as d:
            salida = Path(d) / "p.rsc"
            rc, _ = self._main(["--datos", d, "--categoria", "residencial", "--router", "core-a", "--dias", "7",
                                "--salida", str(salida), "--limite-conexiones", "300"], db)
            self.assertEqual(rc, 0)
            self.assertIn("connection-limit=300,32", salida.read_text(encoding="utf-8"))
        self.assertIn(("servicios", "residencial", "core-a", 7), llamadas)

    def test_sin_base(self):
        db, _ = self._db({}, existe=False)
        with tempfile.TemporaryDirectory() as d:
            rc, err = self._main(["--datos", d, "--categoria", "residencial"], db)
        self.assertEqual(rc, 2)
        self.assertIn("no hay base NetFlow", err)


if __name__ == "__main__":
    unittest.main()
