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
}

_RANGOS = [
    ("udp", 3478, 3481, "STUN/TURN (videollamadas, consolas)"),
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
