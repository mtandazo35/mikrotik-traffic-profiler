#!/usr/bin/env python3
"""Emisor sintético de NetFlow v5 y v9 (solo biblioteca estándar) para probar el colector sin un router.

  python3 tests/emisor_netflow.py --destino 127.0.0.1 --puerto 2055 --version 9 --escenario base --repeticiones 1
  python3 tests/emisor_netflow.py --destino 127.0.0.1 --puerto 2057 --version 5 --origen 127.0.0.1
  python3 tests/emisor_netflow.py --csv          # el escenario como lo imprimiría nfdump -o csv (sin enviar)

Como biblioteca: escenario_base() da los flujos, lineas_csv() su forma CSV de nfdump (la que leen las pruebas
con tests/nfdump_falso.py), paquetes_v9()/paquetes_v5() los paquetes y enviar() los manda por UDP.

Escenario base (el mismo de tests/test_analizar.py, con su registro de respuesta cuando corresponde):
abonados 100.64.1.10–16 y 100.64.1.17; HTTPS, QUIC, tcp/25, barrido tcp/23 a 60 destinos con solo SYN,
DNS a 192.0.2.53, 10.9.9.9:80, 120 pares UDP, entrante a 100.64.1.13:80 y un udp/1900 entrante a 100.64.1.17.
Todas las direcciones son de documentación o reservadas.
"""
import argparse
import ipaddress
import socket
import struct
import sys
import time

TCP, UDP, ICMP = 6, 17, 1
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
CLIENTES, WAN = 7, 1  # ifIndex de ejemplo: interfaz de clientes y salida a internet
PLANTILLA = 256
# (tipo, longitud) de la plantilla v9: IN_BYTES, IN_PKTS, PROTOCOL, TCP_FLAGS, L4_SRC_PORT, IPV4_SRC_ADDR,
# INPUT_SNMP, L4_DST_PORT, IPV4_DST_ADDR, OUTPUT_SNMP, LAST_SWITCHED, FIRST_SWITCHED
CAMPOS_V9 = ((1, 4), (2, 4), (4, 1), (6, 1), (7, 2), (8, 4), (10, 2), (11, 2), (12, 4), (14, 2), (21, 4), (22, 4))
_REGISTRO_V9 = struct.Struct("!IIBBHIHHIHII")   # 34 bytes, en el orden de CAMPOS_V9
_CABECERA_V9 = struct.Struct("!HHIIII")         # versión, registros, uptime, segundos, secuencia, source id
_CABECERA_V5 = struct.Struct("!HHIIIIBBH")      # 24 bytes
_REGISTRO_V5 = struct.Struct("!IIIHHIIIIHHBBBBHHBBH")  # 48 bytes
UPTIME_MS = 3_600_000


def flujo(src, sport, dst, dport, proto=TCP, flags=ACK | PSH | SYN, paquetes=10, bytes_=1000, entrada=CLIENTES,
          salida=WAN):
    """Un registro unidireccional. En ICMP, dport = tipo·256 + código (como lo exporta el router)."""
    return {"src": src, "sport": sport, "dst": dst, "dport": dport, "proto": proto,
            "flags": flags if proto == TCP else 0, "paquetes": paquetes, "bytes": bytes_, "entrada": entrada,
            "salida": salida}


def ida_y_vuelta(src, sport, dst, dport, proto=TCP, bytes_ida=1000, bytes_vuelta=9000):
    """Petición del abonado (entra por clientes) y su respuesta (entra por la WAN)."""
    return [flujo(src, sport, dst, dport, proto, bytes_=bytes_ida),
            flujo(dst, dport, src, sport, proto, paquetes=12, bytes_=bytes_vuelta, entrada=WAN, salida=CLIENTES)]


def escenario_base():
    f = []
    f += ida_y_vuelta("100.64.1.10", 5000, "192.0.2.10", 443)            # HTTPS
    f += ida_y_vuelta("100.64.1.11", 5001, "192.0.2.10", 443, UDP)       # QUIC
    f += ida_y_vuelta("100.64.1.12", 5002, "192.0.2.20", 25)             # SMTP directo
    f += [flujo("198.51.100.4", 4000, "100.64.1.13", 80, entrada=WAN, salida=CLIENTES),   # web en el abonado
          flujo("100.64.1.13", 80, "198.51.100.4", 4000, bytes_=5000)]
    f += [flujo("100.64.1.14", 6000 + i, f"198.51.100.{i}", 23, flags=SYN, paquetes=1, bytes_=60)
          for i in range(1, 61)]                                          # barrido tcp/23, solo SYN
    f += ida_y_vuelta("100.64.1.15", 7000, "192.0.2.53", 53, UDP, 70, 150)   # DNS
    f += ida_y_vuelta("100.64.1.15", 7001, "10.9.9.9", 80)              # destino no público
    f += [flujo("100.64.1.16", 51413, f"203.0.113.{i % 250}", 20000 + i, UDP, paquetes=2, bytes_=200)
          for i in range(120)]                                            # 120 pares UDP (P2P)
    f += [flujo("198.51.100.200", 40000, "100.64.1.17", 1900, UDP, paquetes=1, bytes_=90, entrada=WAN,
                salida=CLIENTES),                                         # SSDP entrante (reflector)
          flujo("100.64.1.17", 1900, "198.51.100.200", 40000, UDP, paquetes=1, bytes_=3000)]
    return f


ESCENARIOS = {"base": escenario_base}


def flags_texto(bits):
    """8 letras CEUAPRSF con '.' en las ausentes, como %flg de nfdump."""
    return "".join(letra if bits & (128 >> i) else "." for i, letra in enumerate("CEUAPRSF"))


def lineas_csv(flujos):
    """Las líneas que imprimiría nfdump -o "csv:%pr,%sa,%sp,%da,%dp,%flg,%ipkt,%ibyt,%fl,%in,%out"."""
    salida = []
    for f in flujos:
        dport = f"{f['dport'] >> 8}.{f['dport'] & 255}" if f["proto"] == ICMP else str(f["dport"])
        salida.append(f"{f['proto']},{f['src']},{f['sport']},{f['dst']},{dport},{flags_texto(f['flags'])},"
                      f"{f['paquetes']},{f['bytes']},1,{f['entrada']},{f['salida']}")
    return salida


def _ip(texto):
    return int(ipaddress.IPv4Address(texto))


def paquetes_v9(flujos, secuencia=0, ahora=None, por_paquete=25, source_id=0):
    """Paquetes v9: cada uno lleva la plantilla 256 y un FlowSet de datos (relleno a 4 bytes)."""
    t = int(time.time() if ahora is None else ahora)
    plantilla = struct.pack("!HH", PLANTILLA, len(CAMPOS_V9)) + b"".join(struct.pack("!HH", *c) for c in CAMPOS_V9)
    fs_plantilla = struct.pack("!HH", 0, 4 + len(plantilla)) + plantilla
    for i in range(0, len(flujos), por_paquete):
        lote = flujos[i:i + por_paquete]
        datos = b"".join(_REGISTRO_V9.pack(f["bytes"], f["paquetes"], f["proto"], f["flags"], f["sport"],
                                           _ip(f["src"]), f["entrada"], f["dport"], _ip(f["dst"]), f["salida"],
                                           UPTIME_MS - 10, UPTIME_MS - 1000) for f in lote)
        relleno = -(4 + len(datos)) % 4
        fs_datos = struct.pack("!HH", PLANTILLA, 4 + len(datos) + relleno) + datos + b"\0" * relleno
        yield _CABECERA_V9.pack(9, 1 + len(lote), UPTIME_MS, t, secuencia, source_id) + fs_plantilla + fs_datos
        secuencia += 1  # v9 numera paquetes


def paquetes_v5(flujos, secuencia=0, ahora=None):
    """Paquetes v5: hasta 30 registros de 48 bytes por paquete."""
    t = int(time.time() if ahora is None else ahora)
    for i in range(0, len(flujos), 30):
        lote = flujos[i:i + 30]
        registros = b"".join(_REGISTRO_V5.pack(_ip(f["src"]), _ip(f["dst"]), 0, f["entrada"], f["salida"],
                                               f["paquetes"], f["bytes"], UPTIME_MS - 1000, UPTIME_MS - 10,
                                               f["sport"], f["dport"], 0, f["flags"], f["proto"], 0, 0, 0, 0, 0, 0)
                             for f in lote)
        yield _CABECERA_V5.pack(5, len(lote), UPTIME_MS, t, 0, secuencia, 0, 0, 0) + registros
        secuencia += len(lote)  # v5 numera flujos


def enviar(destino, puerto, flujos, version=9, repeticiones=1, pausa=0.002, origen=None, secuencia=0):
    """Manda los flujos por UDP; devuelve la secuencia siguiente (para seguir sin 'sequence failures')."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        if origen:
            s.bind((origen, 0))
        for _ in range(repeticiones):
            generador = paquetes_v9(flujos, secuencia) if version == 9 else paquetes_v5(flujos, secuencia)
            for paquete in generador:
                s.sendto(paquete, (destino, puerto))
                secuencia += 1 if version == 9 else struct.unpack("!H", paquete[2:4])[0]
                time.sleep(pausa)
    return secuencia


def main(argv=None):
    p = argparse.ArgumentParser(description="Emisor sintético NetFlow v5/v9 (escenario de prueba).")
    p.add_argument("--destino", default="127.0.0.1")
    p.add_argument("--puerto", type=int, default=2055)
    p.add_argument("--version", type=int, choices=(5, 9), default=9)
    p.add_argument("--escenario", choices=sorted(ESCENARIOS), default="base")
    p.add_argument("--repeticiones", type=int, default=1)
    p.add_argument("--origen", help="IP de origen del envío (la que el colector usa como exportador)")
    p.add_argument("--csv", action="store_true", help="imprimir el escenario en CSV de nfdump y salir")
    a = p.parse_args(argv)
    flujos = ESCENARIOS[a.escenario]()
    if a.csv:
        print("\n".join(lineas_csv(flujos)))
        return 0
    enviar(a.destino, a.puerto, flujos, a.version, a.repeticiones, origen=a.origen)
    print(f"{len(flujos) * a.repeticiones} flujos v{a.version} enviados a {a.destino}:{a.puerto}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
