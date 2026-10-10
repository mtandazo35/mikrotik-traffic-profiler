"""Lectura de la tabla de connection tracking de RouterOS (salida de `print terse`).

Sirve para RouterOS 6 y 7: se leen pares clave=valor sin depender del orden ni de
los campos que traiga cada versión.
"""
import ipaddress
import re
from dataclasses import dataclass

_TOKEN = re.compile(r'\S*"(?:[^"\\]|\\.)*"\S*|\S+')
_CLAVE = re.compile(r"^([a-z][a-z0-9-]*)=(.*)$", re.S)
_PROTO_NUM = {"1": "icmp", "6": "tcp", "17": "udp", "47": "gre", "50": "ipsec-esp", "51": "ipsec-ah"}


def regex_prefijo(cidr):
    """Regex POSIX gruesa para filtrar en el router; el corte exacto por CIDR se hace aquí.

    Se usa `[.]` en vez de `\\.` para no pelear con el escapado de RouterOS ni de la shell.
    """
    red = ipaddress.ip_network(cidr, strict=False)
    if red.version != 4:
        raise ValueError(f"{cidr}: solo IPv4 (/ip firewall connection es IPv4)")
    fijos = red.prefixlen // 8
    if fijos == 0:
        raise ValueError(f"{cidr}: prefijo demasiado amplio para filtrar en el router")
    octetos = str(red.network_address).split(".")[:fijos]
    return "^" + "[.]".join(octetos) + ("(:|$)" if fijos == 4 else "[.]")


def campos(linea):
    """Pares clave=valor de una línea terse. Ignora índice y banderas (SAC, s, d, F…)."""
    salida = {}
    ultima = None
    for token in _TOKEN.findall(linea):
        m = _CLAVE.match(token)
        if m:
            ultima, valor = m.group(1), m.group(2)
            if len(valor) >= 2 and valor[0] == valor[-1] == '"':
                valor = valor[1:-1]
            salida[ultima] = valor
        elif ultima and token.isdigit() and salida[ultima].isdigit():
            # RouterOS agrupa miles con espacio en algunas versiones: "1 234 567"
            salida[ultima] += token
    return salida


def _direccion(texto):
    if not texto:
        return None, None
    ip, _, puerto = texto.partition(":")
    try:
        return ipaddress.IPv4Address(ip), (int(puerto) if puerto.isdigit() else None)
    except ValueError:
        return None, None


def _entero(texto):
    texto = (texto or "").replace(" ", "")
    return int(texto) if texto.isdigit() else 0


@dataclass(frozen=True)
class Conexion:
    proto: str
    src: ipaddress.IPv4Address
    sport: int | None
    dst: ipaddress.IPv4Address
    dport: int | None
    rsrc: ipaddress.IPv4Address | None
    rsport: int | None
    bytes_ida: int
    bytes_vuelta: int
    estado_tcp: str


def conexion(c):
    """Conexion a partir de los campos de una línea, o None si no es una entrada de conntrack."""
    if "protocol" not in c or "src-address" not in c or "dst-address" not in c:
        return None
    src, sport = _direccion(c["src-address"])
    dst, dport = _direccion(c["dst-address"])
    if src is None or dst is None:
        return None
    rsrc, rsport = _direccion(c.get("reply-src-address"))
    proto = _PROTO_NUM.get(c["protocol"], c["protocol"])
    return Conexion(
        proto=proto,
        src=src,
        sport=sport,
        dst=dst,
        dport=dport,
        rsrc=rsrc,
        rsport=rsport,
        # Con FastTrack el contador normal se congela; el de fasttrack sigue. Con hw-offload, ni eso.
        bytes_ida=_entero(c.get("orig-bytes")) + _entero(c.get("orig-fasttrack-bytes")),
        bytes_vuelta=_entero(c.get("repl-bytes")) + _entero(c.get("repl-fasttrack-bytes")),
        estado_tcp=c.get("tcp-state", ""),
    )


def leer(texto):
    """Todas las conexiones de una salida `print terse`."""
    resultado = []
    for linea in texto.splitlines():
        con = conexion(campos(linea))
        if con:
            resultado.append(con)
    return resultado


def _en(ip, redes):
    return ip is not None and any(ip in r for r in redes)


def clasificar(con, redes):
    """(sentido, ip_abonado, puerto_servicio) respecto a las redes de la categoría, o None.

    saliente: el abonado abrió la conexión; puerto_servicio = puerto destino.
    entrante: alguien de fuera abrió hacia el abonado (IP pública ruteada o dst-nat);
              puerto_servicio = puerto del lado del abonado.
    interna:  abonado a abonado de la misma categoría.
    """
    origen = _en(con.src, redes)
    if _en(con.rsrc, redes) and not _en(con.dst, redes):
        destino_ip, destino_puerto = con.rsrc, con.rsport  # dst-nat: el destino real es reply-src
    else:
        destino_ip, destino_puerto = con.dst, con.dport
    destino = _en(destino_ip, redes)
    if origen and destino:
        return "interna", con.src, destino_puerto
    if origen:
        return "saliente", con.src, con.dport
    if destino:
        return "entrante", destino_ip, destino_puerto
    return None
