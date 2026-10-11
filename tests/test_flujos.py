import gzip
import io
import ipaddress
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import trafico
from mtp import flujos, servicios
from mtp.flujos import ENTRANTE, INTERNA, SALIENTE, Agregador, Redes, leer_linea, observaciones
from tests import emisor_netflow

REDES = Redes({"residencial": ["100.64.1.0/24"], "empresarial": ["100.64.2.0/24"]})
VENTANA = 1791682500  # 2026-10-11 01:35 UTC = 2026-10-10 20:35 en Ecuador


def ip(texto):
    return int(ipaddress.IPv4Address(texto))


def obs(linea):
    return observaciones(leer_linea(linea), REDES)


class TestLeerLinea(unittest.TestCase):
    def test_cabecera_y_lineas_invalidas(self):
        self.assertIsNone(leer_linea("proto,srcAddr,srcPort,dstAddr,dstPort,flags,inPackets,inBytes,flows,input,output"))
        self.assertIsNone(leer_linea("6,2001:db8::1,443,2001:db8::2,51000,...A....,1,60,1,7,1"))  # IPv6
        self.assertIsNone(leer_linea("6,100.64.1.10,51514"))
        self.assertIsNone(leer_linea(""))
        self.assertIsNone(leer_linea("6,100.64.1.10,x,192.0.2.10,443,...A....,1,60,1,7,1"))

    def test_tcp(self):
        f = leer_linea("6,100.64.1.10,51514,192.0.2.10,443,...AP.S.,12,4310,1,7,1\n")
        self.assertEqual(f, flujos.Flujo(6, ip("100.64.1.10"), 51514, ip("192.0.2.10"), 443, "...AP.S.",
                                         12, 4310, 1, 7, 1))

    def test_icmp_tipo_codigo(self):
        f = leer_linea("1,100.64.1.15,0,192.0.2.53,8.0,........,1,84,1,7,1")
        self.assertEqual((f.proto, f.dport, f.bytes), (1, 8, 84))


class TestReglas(unittest.TestCase):
    def test_cliente_a_443_y_su_respuesta(self):
        [o] = obs("6,100.64.1.10,51514,192.0.2.10,443,...AP.S.,12,4310,1,7,1")
        self.assertEqual((o.categoria, o.sentido, o.lado, o.puerto, o.subida, o.bajada),
                         ("residencial", SALIENTE, "src", 443, 4310, 0))
        self.assertTrue(o.peticion)
        [r] = obs("6,192.0.2.10,443,100.64.1.10,51514,...AP...,10,9000,1,1,7")
        self.assertEqual((r.sentido, r.lado, r.abonado, r.puerto, r.subida, r.bajada),
                         (SALIENTE, "dst", ip("100.64.1.10"), 443, 0, 9000))
        self.assertFalse(r.peticion)

    def test_servidor_web_en_el_abonado(self):
        [o] = obs("6,198.51.100.4,40000,100.64.1.13,80,......S.,1,60,1,1,7")
        self.assertEqual((o.sentido, o.lado, o.puerto), (ENTRANTE, "dst", 80))
        self.assertTrue(o.peticion)
        [r] = obs("6,100.64.1.13,80,198.51.100.4,40000,...A....,1,60,1,7,1")
        self.assertEqual((r.sentido, r.lado, r.puerto), (ENTRANTE, "src", 80))

    def test_dos_servicios_y_dos_altos_gana_el_menor(self):
        [o] = obs("17,100.64.1.15,53,192.0.2.53,53,........,1,70,1,7,1")
        self.assertEqual((o.sentido, o.puerto), (SALIENTE, 53))
        [o] = obs("17,100.64.1.16,51413,203.0.113.5,40000,........,1,70,1,7,1")
        self.assertEqual((o.sentido, o.puerto), (SALIENTE, 40000))
        [o] = obs("17,100.64.1.16,40000,203.0.113.5,51413,........,1,70,1,7,1")
        self.assertEqual((o.sentido, o.puerto), (ENTRANTE, 40000))

    def test_icmp(self):
        cases = {
            "1,100.64.1.15,0,192.0.2.53,8.0": (SALIENTE, "src"),    # ping del abonado
            "1,192.0.2.53,0,100.64.1.15,0.0": (SALIENTE, "dst"),    # su respuesta
            "1,198.51.100.9,0,100.64.1.15,3.3": (SALIENTE, "dst"),  # error que recibe el abonado
            "1,198.51.100.9,0,100.64.1.15,8.0": (ENTRANTE, "dst"),  # le hacen ping
            "1,100.64.1.15,0,198.51.100.9,0.0": (ENTRANTE, "src"),  # el abonado contesta
        }
        for linea, esperado in cases.items():
            [o] = obs(linea + ",........,1,84,1,7,1")
            self.assertEqual((o.sentido, o.lado, o.puerto), esperado + (0,), linea)

    def test_gre_siempre_saliente(self):
        [o] = obs("47,100.64.1.20,0,192.0.2.30,0,........,5,500,1,7,1")
        self.assertEqual((o.sentido, o.puerto), (SALIENTE, 0))
        [o] = obs("47,192.0.2.30,0,100.64.1.20,0,........,5,500,1,1,7")
        self.assertEqual((o.sentido, o.lado, o.bajada), (SALIENTE, "dst", 500))

    def test_interna_y_entre_categorias(self):
        [o] = obs("6,100.64.1.10,50000,100.64.1.11,443,...A....,1,60,1,7,7")
        self.assertEqual((o.sentido, o.abonado, o.puerto), (INTERNA, ip("100.64.1.10"), 443))
        a, b = obs("6,100.64.1.10,50000,100.64.2.5,443,...A....,1,60,1,7,8")
        self.assertEqual((a.categoria, a.sentido, a.lado, a.subida), ("residencial", SALIENTE, "src", 60))
        self.assertEqual((b.categoria, b.sentido, b.lado, b.bajada), ("empresarial", ENTRANTE, "dst", 60))
        self.assertEqual(obs("6,192.0.2.1,50000,198.51.100.5,443,...A....,1,60,1,1,2"), [])


class TestServicios(unittest.TestCase):
    def test_clave_hasta_etiqueta(self):
        casos = [("tcp", 443, 443, 443, "tcp/443", "HTTPS"),
                 ("udp", 3479, 3478, 3481, "udp/3478-3481", "STUN/TURN (videollamadas, consolas)"),
                 ("tcp", 40000, -1, 49151, "tcp/1024-49151", "otros puertos sin catálogo"),
                 ("udp", 50000, -2, 65535, "udp/49152-65535", "efímero / dinámico"),
                 ("icmp", 0, 0, 0, "icmp", "ICMP")]
        for proto, puerto, clave, hasta, etiqueta, nombre in casos:
            k = servicios.clave(proto, puerto)
            self.assertEqual((k, servicios.hasta(proto, k), servicios.etiqueta(proto, k),
                              servicios.nombre_clave(proto, k)), (clave, hasta, etiqueta, nombre), (proto, puerto))
        self.assertEqual(servicios.clave("udp", 5060), 5060)  # exacto dentro de un rango: gana el exacto
        self.assertEqual(servicios.clave("tcp", 1023), 1023)

    def test_proto_y_es_servicio(self):
        self.assertEqual([servicios.proto_nombre(n) for n in (6, 17, 1, 47, 50, 51, 99)],
                         ["tcp", "udp", "icmp", "gre", "ipsec-esp", "ipsec-ah", "99"])
        self.assertTrue(servicios.es_servicio("tcp", 22))
        self.assertTrue(servicios.es_servicio("udp", 19305))
        self.assertFalse(servicios.es_servicio("tcp", 40000))
        self.assertEqual(servicios.rango("udp", 3480), (3478, 3481, "STUN/TURN (videollamadas, consolas)"))
        self.assertIsNone(servicios.rango("tcp", 3480))


class TestAgregacion(unittest.TestCase):
    """Un archivo con el escenario base, como lo dejaría nfdump."""

    @classmethod
    def setUpClass(cls):
        cls.ag = Agregador("core-a", VENTANA)
        for linea in emisor_netflow.lineas_csv(emisor_netflow.escenario_base()):
            fl = leer_linea(linea)
            cls.ag.agregar(fl, observaciones(fl, Redes({"residencial": ["100.64.1.0/24"]})))
        cls.f = {t: list(filas) for t, filas in cls.ag.filas().items()}

    def test_abonados_por_servicio(self):
        servicio = {(s, p, k): mx for _, _, _, s, p, k, *_, mx in self.f["servicio_dia"]}
        for clave in [(SALIENTE, 6, 443), (SALIENTE, 17, 443), (SALIENTE, 6, 25), (SALIENTE, 6, 23),
                      (SALIENTE, 17, 53), (SALIENTE, 6, 80), (ENTRANTE, 6, 80), (ENTRANTE, 17, 1900)]:
            self.assertEqual(servicio.get(clave), 1, clave)
        self.assertEqual(servicio[(SALIENTE, 17, -1)], 1)  # los pares UDP altos van al cubo
        [total] = self.f["total_hora"]
        self.assertEqual(total[-1], 8)  # abonados distintos en el minuto (100.64.1.10–17)
        self.assertEqual(total[0], VENTANA - VENTANA % 3600)

    def test_bytes_por_sentido(self):
        esc = emisor_netflow.escenario_base()
        subida = sum(f["bytes"] for f in esc if f["src"].startswith("100.64.1."))
        bajada = sum(f["bytes"] for f in esc if f["dst"].startswith("100.64.1."))
        self.assertEqual((self.ag.subida, self.ag.bajada), (subida, bajada))

    def test_senales(self):
        senales = {(t, d, a): (fl, rem) for _, _, _, t, d, a, fl, _, rem, _ in self.f["senal_dia"]}
        self.assertEqual(senales[("barrido", "tcp/23", ip("100.64.1.14"))], (60, 60))
        self.assertEqual(senales[("p2p", "", ip("100.64.1.16"))][1], 120)
        self.assertIn(("sensible", "tcp/25", ip("100.64.1.12")), senales)
        self.assertEqual(senales[("reflector", "udp/1900", ip("100.64.1.17"))], (2, 1))
        self.assertNotIn("barrido", {t for t, d, a in senales if d == "tcp/443"})

    def test_dns_y_no_publicos(self):
        self.assertIn((17, 53, ip("192.0.2.53")), {(p, pu, s) for _, _, _, p, pu, s, _ in self.f["dns_dia"]})
        self.assertIn(ip("10.9.9.0"), {red for _, _, _, red, _, _ in self.f["no_publico_dia"]})

    def test_metricas_por_abonado(self):
        ab = {fila[3]: tuple(fila[9:]) for fila in self.f["abonado_dia"]}
        # max_flujos, max_tcp_nuevas, max_udp, max_ips, max_puertos, max_peers_udp, max_syn
        self.assertEqual(ab[ip("100.64.1.14")], (60, 60, 0, 60, 1, 0, 60))
        self.assertEqual(ab[ip("100.64.1.10")], (1, 1, 0, 1, 1, 0, 0))   # SYN+ACK: conexión nueva, no syn suelto
        self.assertEqual(ab[ip("100.64.1.16")][5], 120)
        self.assertEqual(ab[ip("100.64.1.13")], (0,) * 7)  # solo entrante: sin peticiones salientes
        # histograma: una observación por métrica por cada abonado con peticiones salientes (6: .10-.12 y .14-.16)
        n = {}
        for _, _, _, metrica, _, cantidad in self.f["hist_dia"]:
            n[metrica] = n.get(metrica, 0) + cantidad
        self.assertEqual(set(n.values()), {6})


class TestMemoria(unittest.TestCase):
    def test_claves_cuenta_los_miembros_de_los_conjuntos(self):
        # 200 pares UDP de un abonado al mismo puerto: lo que crece son los conjuntos (5-tuplas, IPs, pares,
        # remotos por puerto), no las entradas de diccionario; el tope tiene que verlos
        ag = Agregador("core-a", VENTANA)
        redes = Redes({"residencial": ["100.64.1.0/24"]})
        for i in range(200):
            fl = leer_linea(f"17,100.64.1.16,51413,203.0.113.{i},40000,........,2,200,1,7,1")
            ag.agregar(fl, observaciones(fl, redes))
        self.assertGreaterEqual(ag.claves(), 5 * 200)
        [abonado] = [f for f in ag.filas()["abonado_dia"]]
        self.assertEqual(abonado[9:], (200, 0, 200, 200, 1, 200, 0))  # métricas intactas con la codificación


class TestDescargaAsn(unittest.TestCase):
    TSV = "".join(f"198.18.0.{i}\t198.18.0.{i}\t64500\tEC\tEJEMPLO\n" for i in range(200)).encode()

    def test_descarga_validada_y_atomica(self):
        bueno = gzip.compress(self.TSV)
        with tempfile.TemporaryDirectory() as d:
            destino = Path(d) / "ip2asn-v4.tsv.gz"
            destino.write_bytes(b"tabla anterior")
            for malo in (bueno[:len(bueno) // 2], gzip.compress(b"<html>503</html>"), b"no es gzip"):
                with self.assertRaises(ValueError):
                    trafico.descargar_asn(destino, abrir=lambda pedido, timeout, x=malo: io.BytesIO(x), minimo=100)
                self.assertEqual(destino.read_bytes(), b"tabla anterior")  # la buena no se toca
                self.assertEqual([p.name for p in Path(d).iterdir()], [destino.name])  # sin temporales
            trafico.descargar_asn(destino, abrir=lambda pedido, timeout: io.BytesIO(bueno), minimo=100)
            self.assertEqual(destino.read_bytes(), bueno)

    def test_no_reintenta_cada_minuto(self):
        with tempfile.TemporaryDirectory() as d:
            destino = Path(d) / "ip2asn-v4.tsv.gz"
            destino.write_bytes(b"x")
            viejo = time.time() - 30 * 86400
            os.utime(destino, (viejo, viejo))
            intento = Path(d) / "ip2asn-v4.intento"
            intento.touch()
            argv = ["trafico.py", "--datos", d, "asn", "--timeout", "15", "--reintento-horas", "1"]
            with mock.patch.object(sys, "argv", argv), mock.patch.object(trafico, "descargar_asn") as bajar:
                trafico.main()  # intentó hace un momento: no vuelve a esperar a iptoasn
                self.assertFalse(bajar.called)
                hace_2h = time.time() - 7200
                os.utime(intento, (hace_2h, hace_2h))
                trafico.main()
                bajar.assert_called_once_with(destino, timeout=15.0)


class TestVarios(unittest.TestCase):
    def test_router_por_exportador(self):
        inv = {"routers": {"a": {"host": "192.0.2.1"}, "b": {"host": "192.0.2.2", "exportador": "198.51.100.9"},
                           "c": {"host": "198.51.100.9"}}}
        self.assertEqual(flujos.router_por_exportador(inv, "192.0.2.1"), "a")
        self.assertEqual(flujos.router_por_exportador(inv, "198.51.100.9"), "b")  # exportador antes que host
        self.assertIsNone(flujos.router_por_exportador(inv, "192.0.2.2"))  # b exporta desde otra IP
        self.assertIsNone(flujos.router_por_exportador(inv, "203.0.113.1"))
        self.assertIsNone(flujos.router_por_exportador({}, "203.0.113.1"))

    def test_filtro_nfdump(self):
        self.assertEqual(flujos.filtro_nfdump(["100.64.0.0/22", "198.51.100.7/26"]),
                         "net 100.64.0.0/22 or net 198.51.100.0/26")
        redes = Redes({"residencial": ["100.64.1.0/24", "100.64.0.0/24"], "empresarial": ["198.51.100.0/26"]})
        self.assertEqual(redes.cidrs, ["100.64.0.0/23", "198.51.100.0/26"])  # contiguos se juntan
        self.assertEqual(redes.categoria_de(ip("100.64.0.200")), "residencial")
        self.assertEqual(redes.categoria_de(ip("198.51.100.63")), "empresarial")
        self.assertIsNone(redes.categoria_de(ip("198.51.100.64")))

    def test_tabla_asn(self):
        tsv = ("192.0.2.0\t192.0.2.255\t64500\tEC\tEJEMPLO-A\n"
               "198.51.100.0\t198.51.100.255\t0\tNone\tNot routed\n"
               "203.0.113.0\t203.0.113.255\t64501\tUS\tEJEMPLO-B\n")
        with tempfile.TemporaryDirectory() as d:
            ruta = Path(d) / "ip2asn-v4.tsv.gz"
            with gzip.open(ruta, "wt", encoding="utf-8") as f:
                f.write(tsv)
            t = flujos.TablaAsn(ruta)
            self.assertEqual(len(t), 2)  # el ASN 0 (no enrutado) se descarta
            self.assertEqual([t.buscar(ip(x)) for x in ("192.0.2.7", "198.51.100.5", "203.0.113.255", "100.64.0.1")],
                             [64500, 0, 64501, 0])
            self.assertEqual(list(t.nombres()), [(64500, "EJEMPLO-A", "EC"), (64501, "EJEMPLO-B", "US")])
            t.guardar_cache(Path(d) / "c")
            c = flujos.TablaAsn.desde_cache(Path(d) / "c")
            self.assertEqual([c.buscar(ip(x)) for x in ("192.0.2.7", "198.51.100.5", "203.0.113.1")], [64500, 0, 64501])
            (Path(d) / "malo").write_bytes(b"xx")
            with self.assertRaises(ValueError):
                flujos.TablaAsn.desde_cache(Path(d) / "malo")


if __name__ == "__main__":
    unittest.main()
