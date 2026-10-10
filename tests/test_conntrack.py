import ipaddress
import unittest

from mtp.conntrack import campos, clasificar, conexion, leer, regex_prefijo

RES = [ipaddress.ip_network("100.64.1.0/24")]

LINEA_TCP = (" 0  SAC  s  protocol=tcp src-address=100.64.1.10:51000 dst-address=192.0.2.10:443 "
             "reply-src-address=192.0.2.10:443 reply-dst-address=203.0.113.5:51000 tcp-state=established "
             "timeout=23h59m50s orig-packets=10 orig-bytes=1 200 orig-fasttrack-bytes=300 "
             "repl-packets=12 repl-bytes=15 000 connection-mark=\"res idencial\"")


class TestCampos(unittest.TestCase):
    def test_miles_con_espacio_y_comillas(self):
        c = campos(LINEA_TCP)
        self.assertEqual(c["orig-bytes"], "1200")
        self.assertEqual(c["repl-bytes"], "15000")
        self.assertEqual(c["connection-mark"], "res idencial")
        self.assertEqual(c["tcp-state"], "established")

    def test_bytes_suman_fasttrack(self):
        con = conexion(campos(LINEA_TCP))
        self.assertEqual(con.bytes_ida, 1500)
        self.assertEqual(con.dport, 443)

    def test_icmp_sin_puerto_y_protocolo_numerico(self):
        con = conexion(campos(" 3  SAC  protocol=1 src-address=100.64.1.7 dst-address=192.0.2.9"))
        self.assertEqual(con.proto, "icmp")
        self.assertIsNone(con.dport)

    def test_lineas_que_no_son_conexiones(self):
        self.assertEqual(leer("Flags: S - seen-reply, A - assured\n\n" + LINEA_TCP), [conexion(campos(LINEA_TCP))])


class TestRegex(unittest.TestCase):
    def test_prefijos(self):
        self.assertEqual(regex_prefijo("100.64.1.0/24"), "^100[.]64[.]1[.]")
        self.assertEqual(regex_prefijo("100.64.0.0/22"), "^100[.]64[.]")
        self.assertEqual(regex_prefijo("100.64.1.5/32"), "^100[.]64[.]1[.]5(:|$)")

    def test_rechaza_demasiado_amplio_e_ipv6(self):
        with self.assertRaises(ValueError):
            regex_prefijo("0.0.0.0/0")
        with self.assertRaises(ValueError):
            regex_prefijo("2001:db8::/32")


class TestClasificar(unittest.TestCase):
    def _con(self, linea):
        return conexion(campos(linea))

    def test_saliente(self):
        self.assertEqual(clasificar(self._con(LINEA_TCP), RES), ("saliente", ipaddress.ip_address("100.64.1.10"), 443))

    def test_entrante_por_dstnat(self):
        con = self._con("protocol=tcp src-address=198.51.100.4:40000 dst-address=203.0.113.5:8080 "
                        "reply-src-address=100.64.1.20:80 reply-dst-address=198.51.100.4:40000")
        self.assertEqual(clasificar(con, RES), ("entrante", ipaddress.ip_address("100.64.1.20"), 80))

    def test_entrante_ip_publica_ruteada(self):
        con = self._con("protocol=udp src-address=198.51.100.4:4444 dst-address=100.64.1.30:1900 "
                        "reply-src-address=100.64.1.30:1900 reply-dst-address=198.51.100.4:4444")
        self.assertEqual(clasificar(con, RES), ("entrante", ipaddress.ip_address("100.64.1.30"), 1900))

    def test_vecino_fuera_del_cidr_no_cuenta(self):
        con = self._con("protocol=tcp src-address=100.64.10.10:5000 dst-address=192.0.2.1:443 "
                        "reply-src-address=192.0.2.1:443 reply-dst-address=203.0.113.5:5000")
        self.assertIsNone(clasificar(con, RES))


if __name__ == "__main__":
    unittest.main()
