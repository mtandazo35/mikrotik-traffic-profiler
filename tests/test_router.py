import unittest

from mtp.router import DESCUBRIR, _filtro, comprobar_lectura


class TestSoloLectura(unittest.TestCase):
    def test_acepta_prints(self):
        for orden in DESCUBRIR + [f"/ip firewall connection print terse without-paging {_filtro('100.64.1.0/24')}",
                                  f"/ip firewall connection print count-only {_filtro('100.64.1.5/32')}"]:
            comprobar_lectura(orden)

    def test_rechaza_escrituras_y_encadenados(self):
        for orden in [
            "/ip firewall filter add chain=forward action=drop",
            "/system reboot",
            "/system reboot print",
            "/ip firewall connection print; /system reboot",
            "/ip firewall connection print where [/system reboot]",
            "/export",
            "/export print",
            "/tool torch print",
            "/ip firewall filter reset-counters print",
            ":put [/system reboot]",
            '/ip firewall connection print where src-address~"$[/system reboot]"',
            '/ip firewall connection print where src-address~"x" "[/system reboot]',
            '/ip firewall connection print where src-address~"abc"',
        ]:
            with self.assertRaises(PermissionError, msg=orden):
                comprobar_lectura(orden)


if __name__ == "__main__":
    unittest.main()
