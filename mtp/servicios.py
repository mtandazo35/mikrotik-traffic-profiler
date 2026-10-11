"""Nombre de servicio por protocolo/puerto destino. Solo orienta la lectura del informe."""

_EXACTOS = {
    ("tcp", 80): "HTTP",
    ("tcp", 443): "HTTPS",
    ("udp", 443): "QUIC (HTTP/3)",
    ("udp", 53): "DNS",
    ("tcp", 53): "DNS/TCP",
    ("tcp", 853): "DNS sobre TLS",
    ("udp", 853): "DNS sobre QUIC",
    ("udp", 123): "NTP",
    ("tcp", 22): "SSH",
    ("tcp", 23): "Telnet",
    ("tcp", 2323): "Telnet alterno (botnets IoT)",
    ("tcp", 21): "FTP",
    ("tcp", 25): "SMTP (envío directo)",
    ("tcp", 465): "SMTPS",
    ("tcp", 587): "SMTP submission",
    ("tcp", 110): "POP3",
    ("tcp", 995): "POP3S",
    ("tcp", 143): "IMAP",
    ("tcp", 993): "IMAPS",
    ("tcp", 135): "MS RPC",
    ("udp", 137): "NetBIOS nombres",
    ("udp", 138): "NetBIOS datagramas",
    ("tcp", 139): "NetBIOS sesión",
    ("tcp", 445): "SMB",
    ("tcp", 3389): "RDP",
    ("udp", 3389): "RDP/UDP",
    ("tcp", 5900): "VNC",
    ("udp", 1900): "SSDP/UPnP",
    ("udp", 5353): "mDNS",
    ("udp", 11211): "memcached",
    ("udp", 19): "chargen",
    ("udp", 389): "CLDAP",
    ("tcp", 1723): "PPTP",
    ("udp", 1194): "OpenVPN",
    ("tcp", 1194): "OpenVPN/TCP",
    ("udp", 51820): "WireGuard",
    ("udp", 500): "IPsec IKE",
    ("udp", 4500): "IPsec NAT-T",
    ("tcp", 5222): "XMPP / WhatsApp",
    ("tcp", 5223): "Apple push",
    ("tcp", 5228): "Google push (FCM)",
    ("tcp", 1935): "RTMP",
    ("tcp", 8080): "HTTP alterno",
    ("tcp", 8443): "HTTPS alterno",
    ("udp", 5060): "SIP",
    ("tcp", 5060): "SIP/TCP",
    ("udp", 3074): "Xbox Live",
    ("tcp", 3074): "Xbox Live",
    ("tcp", 7547): "TR-069 (CWMP)",
    ("tcp", 8291): "Winbox",
    ("tcp", 8728): "API RouterOS",
    ("tcp", 1883): "MQTT",
    ("tcp", 8883): "MQTT/TLS",
    ("udp", 69): "TFTP",
    ("udp", 161): "SNMP",
    ("tcp", 554): "RTSP (cámaras)",
    ("tcp", 34567): "DVR XMEye",
    ("tcp", 37777): "DVR/cámara Dahua",
    ("tcp", 8000): "DVR/cámara Hikvision",
}

_RANGOS = [
    ("udp", 3478, 3481, "STUN/TURN (videollamadas, consolas)"),
    ("tcp", 6881, 6889, "BitTorrent"),
    ("udp", 6881, 6889, "BitTorrent"),
    ("udp", 19302, 19309, "STUN Google (Meet/Hangouts)"),
    ("udp", 8801, 8810, "Zoom"),
    ("udp", 27000, 27050, "Steam / juegos Valve"),
    ("tcp", 27014, 27050, "Steam"),
    ("udp", 5000, 5500, "Juegos / VoIP (rango ancho)"),
    ("tcp", 16464, 16471, "Puertos C2 Mēris"),
    ("udp", 10000, 20000, "RTP / medios"),
]


def nombre(proto, puerto):
    if puerto is None:
        return proto.upper()
    if (proto, puerto) in _EXACTOS:
        return _EXACTOS[(proto, puerto)]
    for p, desde, hasta, texto in _RANGOS:
        if p == proto and desde <= puerto <= hasta:
            return texto
    if puerto >= 49152:
        return "efímero / dinámico"
    return ""


# ---------- claves de servicio (NetFlow) ----------
# La presencia por abonado y los agregados por servicio no guardan el puerto exacto de los puertos altos
# sin catálogo: los juntan en dos cubos para no multiplicar filas con puertos aleatorios (P2P, juegos).

PUERTO_ALTO = -1      # 1024–49151 sin catálogo
PUERTO_EFIMERO = -2   # 49152–65535
_PROTO_NUM = {1: "icmp", 6: "tcp", 17: "udp", 47: "gre", 50: "ipsec-esp", 51: "ipsec-ah"}
_CON_PUERTO = ("tcp", "udp")


def proto_nombre(numero):
    """Número de protocolo IP como texto, igual que conntrack: 6 -> "tcp"; 99 -> "99"."""
    try:
        return _PROTO_NUM.get(int(numero), str(numero))
    except (TypeError, ValueError):
        return str(numero)


def rango(proto, puerto):
    """(desde, hasta, texto) del primer rango con nombre que contiene el puerto, o None."""
    if puerto is None:
        return None
    for p, desde, hasta_, texto in _RANGOS:
        if p == proto and desde <= puerto <= hasta_:
            return desde, hasta_, texto
    return None


def es_servicio(proto, puerto):
    """Puerto bien conocido (< 1024), del catálogo exacto o de un rango con nombre."""
    if puerto is None or proto not in _CON_PUERTO:
        return False
    return puerto < 1024 or (proto, puerto) in _EXACTOS or rango(proto, puerto) is not None


def clave(proto, puerto):
    """Clave de servicio: puerto exacto | inicio del rango con nombre | -1 | -2 ; 0 si no es tcp/udp."""
    if proto not in _CON_PUERTO or puerto is None:
        return 0
    if puerto < 1024 or (proto, puerto) in _EXACTOS:
        return puerto
    r = rango(proto, puerto)
    if r:
        return r[0]
    return PUERTO_EFIMERO if puerto >= 49152 else PUERTO_ALTO


def hasta(proto, clave_):
    """Último puerto que cubre una clave: fin del rango; la misma si es exacta; 49151 / 65535 para -1/-2."""
    if proto not in _CON_PUERTO:
        return 0
    if clave_ == PUERTO_ALTO:
        return 49151
    if clave_ == PUERTO_EFIMERO:
        return 65535
    if clave_ < 1024 or (proto, clave_) in _EXACTOS:
        return clave_
    for p, desde, hasta_, _ in _RANGOS:
        if p == proto and desde == clave_:
            return hasta_
    return clave_


def _desde(clave_):
    return {PUERTO_ALTO: 1024, PUERTO_EFIMERO: 49152}.get(clave_, clave_)


def etiqueta(proto, clave_):
    """"tcp/443", "udp/3478-3481", "tcp/1024-49151", "udp/49152-65535", "icmp"."""
    if proto not in _CON_PUERTO:
        return proto
    desde, fin = _desde(clave_), hasta(proto, clave_)
    return f"{proto}/{desde}" if desde == fin else f"{proto}/{desde}-{fin}"


def nombre_clave(proto, clave_):
    """Nombre legible de una clave: el de nombre(), o el del cubo."""
    if proto not in _CON_PUERTO:
        return nombre(proto, None)
    if clave_ == PUERTO_ALTO:
        return "otros puertos sin catálogo"
    if clave_ == PUERTO_EFIMERO:
        return "efímero / dinámico"
    return nombre(proto, clave_)
