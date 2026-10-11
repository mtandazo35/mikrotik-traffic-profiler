"""Clasificación de servicios de una categoría (NetFlow) y propuesta de firewall en modo detección.

  python3 -m mtp.firewall --datos DIR --categoria residencial [--router X] [--dias 7] [--salida F] [--forzar]

No toca ningún router: la propuesta es un .rsc para revisión humana, sin IPs (la address-list de la categoría
la completa el operador). Cada bloqueo nace como detección (address-list DET-…) con el drop gemelo desactivado.
"""
import argparse
import copy
import math
import re
import sys
import unicodedata
from datetime import date
from pathlib import Path

from . import servicios

PCT_ESENCIAL = 5.0  # ≥ 5 % de los abonados de la categoría en el periodo
PCT_USADO = 0.5     # 0,5 % – 5 %
MIN_DIAS = 7
MIN_ABONADOS = 50

# (sentido, proto, desde, hasta, motivo). Lo que el agente trafico-mikrotik nunca bloquea en la capa de categoría.
NUNCA_BLOQUEAR = {
    ("saliente", "tcp", 80, 80, "web"),
    ("saliente", "tcp", 443, 443, "web cifrada"),
    ("saliente", "udp", 443, 443, "QUIC (HTTP/3)"),
    ("saliente", "udp", 53, 53, "DNS"),
    ("saliente", "udp", 123, 123, "NTP"),
    ("saliente", "udp", 3478, 3481, "STUN/TURN (videollamadas, consolas)"),
    ("saliente", "udp", 19302, 19309, "STUN Google (Meet)"),
    ("saliente", "udp", 500, 500, "IPsec IKE (VPN de trabajo)"),
    ("saliente", "udp", 4500, 4500, "IPsec NAT-T (VPN de trabajo)"),
    ("saliente", "udp", 1194, 1194, "OpenVPN (VPN de trabajo)"),
    ("saliente", "tcp", 1194, 1194, "OpenVPN/TCP (VPN de trabajo)"),
    ("saliente", "udp", 51820, 51820, "WireGuard (VPN de trabajo)"),
    ("saliente", "tcp", 1723, 1723, "PPTP (VPN de trabajo)"),
    ("saliente", "gre", 0, 0, "GRE (PPTP)"),
    ("saliente", "tcp", 465, 465, "correo de clientes (SMTPS)"),
    ("saliente", "tcp", 587, 587, "correo de clientes (submission)"),
    ("saliente", "tcp", 993, 993, "correo de clientes (IMAPS)"),
    ("saliente", "tcp", 995, 995, "correo de clientes (POP3S)"),
    ("saliente", "tcp", 853, 853, "DNS cifrado: decisión de política DNS"),
    ("saliente", "udp", 853, 853, "DNS cifrado: decisión de política DNS"),
}

RIESGO_SALIENTE = {
    ("saliente", "tcp", 25, 25, "SMTP directo (spam desde equipos infectados)"),
    ("saliente", "tcp", 23, 23, "Telnet (botnets IoT)"),
    ("saliente", "tcp", 2323, 2323, "Telnet alterno (botnets IoT)"),
    ("saliente", "tcp", 135, 135, "MS RPC hacia internet"),
    ("saliente", "tcp", 139, 139, "NetBIOS sesión hacia internet"),
    ("saliente", "tcp", 445, 445, "SMB hacia internet"),
    ("saliente", "udp", 137, 137, "NetBIOS nombres hacia internet"),
    ("saliente", "udp", 138, 138, "NetBIOS datagramas hacia internet"),
    ("saliente", "tcp", 16464, 16471, "puertos C2 Mēris"),
}

RIESGO_ENTRANTE = {
    ("entrante", "udp", 53, 53, "DNS abierto (reflector)"),
    ("entrante", "udp", 123, 123, "NTP (reflector)"),
    ("entrante", "udp", 1900, 1900, "SSDP/UPnP (reflector)"),
    ("entrante", "udp", 11211, 11211, "memcached (reflector)"),
    ("entrante", "udp", 19, 19, "chargen (reflector)"),
    ("entrante", "udp", 389, 389, "CLDAP (reflector)"),
    ("entrante", "udp", 161, 161, "SNMP (reflector)"),
    ("entrante", "udp", 5353, 5353, "mDNS (reflector)"),
    ("entrante", "tcp", 23, 23, "Telnet expuesto"),
    ("entrante", "tcp", 2323, 2323, "Telnet alterno expuesto"),
    ("entrante", "tcp", 135, 135, "MS RPC expuesto"),
    ("entrante", "tcp", 139, 139, "NetBIOS expuesto"),
    ("entrante", "tcp", 445, 445, "SMB expuesto"),
    ("entrante", "tcp", 3389, 3389, "RDP expuesto"),
    ("entrante", "tcp", 5900, 5900, "VNC expuesto"),
    ("entrante", "tcp", 7547, 7547, "TR-069 del CPE expuesto"),
    ("entrante", "tcp", 8291, 8291, "Winbox expuesto"),
    ("entrante", "tcp", 8728, 8728, "API RouterOS expuesta"),
}

CLASES = ("riesgo", "esencial", "usado", "minoritario", "no_observado")
_PREFIJOS = {"residencial": "RES", "empresarial": "EMP"}


# ---------- clasificación ----------

def _rango(fila):
    """(desde, hasta) del puerto de la fila; None para los cubos -1/-2 (puertos altos sin catálogo).

    Los cubos no se cruzan con las listas: por construcción (servicios.clave) todo puerto de RIESGO_* o
    NUNCA_BLOQUEAR es < 1024, del catálogo exacto o de un rango con nombre, así que nunca cae en un cubo."""
    p = fila.get("puerto")
    if p is None:
        return 0, 0
    if p < 0:
        return None
    h = fila.get("puerto_hasta")
    return p, h if isinstance(h, int) and h >= p else p


def _riesgo(fila):
    """Entrada de RIESGO_* que CONTIENE la fila. Contener, no solapar: el rango con nombre udp/10000-20000 (RTP)
    solapa con udp/11211 (memcached, con clave propia en el catálogo) y no por eso es un reflector."""
    r = _rango(fila)
    if r is None:
        return None
    for ent in sorted(RIESGO_SALIENTE | RIESGO_ENTRANTE):
        if ent[0] == fila.get("sentido") and ent[1] == fila.get("proto") and ent[2] <= r[0] and r[1] <= ent[3]:
            return ent
    return None


def _protegido(fila):
    """Entrada de NUNCA_BLOQUEAR que SOLAPA la fila (en la duda, se protege)."""
    r = _rango(fila)
    if r is None:
        return None
    for ent in sorted(NUNCA_BLOQUEAR):
        if ent[0] == fila.get("sentido") and ent[1] == fila.get("proto") and r[0] <= ent[3] and r[1] >= ent[2]:
            return ent
    return None


def _pct(fila, total):
    """% de abonados recalculado con los conteos (el pct_abonados viene redondeado a 1 decimal)."""
    if total:
        return (fila.get("abonados") or 0) * 100.0 / total
    return float(fila.get("pct_abonados") or 0)


def _texto_pct(v):
    return f"{v:.2f}".rstrip("0").rstrip(".")


def etiqueta(proto, desde, hasta):
    if proto not in ("tcp", "udp"):
        return proto
    return f"{proto}/{desde}" if desde == hasta else f"{proto}/{desde}-{hasta}"


def clasificar(servicios_cat, percentiles=None):
    """Clase de cada fila de flujos_db.servicios_categoria(): esencial | usado | minoritario | riesgo | no_observado.

    Reglas en orden: contenida en RIESGO_* → riesgo (revisar=True si pct ≥ PCT_ESENCIAL); solapa NUNCA_BLOQUEAR o
    pct ≥ PCT_ESENCIAL → esencial; pct ≥ PCT_USADO → usado; si no → minoritario. Más una fila no_observado por
    cada entrada de RIESGO_* y del catálogo exacto sin tráfico."""
    salida = copy.deepcopy(servicios_cat)
    total = salida.get("abonados_total") or 0
    filas = []
    for f in salida.get("filas", []):
        f = dict(f)
        pct = _pct(f, total)
        f["pct_decision"] = round(pct, 2)
        evidencia = f"{_texto_pct(pct)} % de abonados"
        riesgo, protegido = _riesgo(f), _protegido(f)
        f["riesgo"] = bool(riesgo)
        if riesgo:
            f["clase"], f["revisar"] = "riesgo", pct >= PCT_ESENCIAL
            f["motivo"] = f"{riesgo[4]}: {evidencia}" + (f" (≥ {PCT_ESENCIAL:g} %: masivo, decidir a mano)" if f["revisar"] else "")
        elif protegido:
            f["clase"], f["revisar"] = "esencial", False
            f["motivo"] = f"no se bloquea: {protegido[4]} ({evidencia})"
        elif pct >= PCT_ESENCIAL:
            f["clase"], f["revisar"] = "esencial", False
            f["motivo"] = f"{evidencia} ≥ {PCT_ESENCIAL:g} %"
        elif pct >= PCT_USADO:
            f["clase"], f["revisar"] = "usado", False
            f["motivo"] = f"{evidencia}, entre {PCT_USADO:g} % y {PCT_ESENCIAL:g} %"
        else:
            f["clase"], f["revisar"] = "minoritario", False
            f["motivo"] = f"{evidencia} < {PCT_USADO:g} %"
        filas.append(f)

    vistos = [(f.get("sentido"), f.get("proto"), _rango(f)) for f in filas]

    def observado(sentido, proto, desde, hasta):
        # misma semántica que _riesgo: la fila observada tiene que caer DENTRO de la entrada. Con solape, ver
        # udp/10000-20000 (RTP) borraría la fila no observada de udp/11211 (memcached), que tiene clave propia.
        return any(s == sentido and p == proto and r is not None and desde <= r[0] and r[1] <= hasta
                   for s, p, r in vistos)

    candidatos = sorted(RIESGO_SALIENTE | RIESGO_ENTRANTE)
    candidatos += sorted(("saliente", p, n, n, servicios.nombre(p, n)) for p, n in servicios._EXACTOS)
    hechos = set()
    for sentido, proto, desde, hasta, texto in candidatos:
        clave = (sentido, proto, desde, hasta)
        if clave in hechos or observado(sentido, proto, desde, hasta):
            continue
        hechos.add(clave)
        es_riesgo = any(ent[:4] == clave for ent in RIESGO_SALIENTE | RIESGO_ENTRANTE)
        filas.append({"sentido": sentido, "proto": proto, "puerto": desde, "puerto_hasta": hasta,
                      "etiqueta": etiqueta(proto, desde, hasta), "servicio": servicios.nombre(proto, desde),
                      "abonados": 0, "pct_abonados": 0.0, "pct_decision": 0.0, "flujos": 0, "bytes": 0,
                      "dias_observado": 0, "clase": "no_observado", "revisar": False, "riesgo": es_riesgo,
                      "motivo": (f"riesgo conocido ({texto}) sin tráfico en el periodo" if es_riesgo
                                 else "del catálogo, sin tráfico en el periodo")})

    filas.sort(key=lambda f: (CLASES.index(f["clase"]), -(f.get("abonados") or 0), -(f.get("flujos") or 0),
                              f.get("sentido") or "", f.get("etiqueta") or ""))
    salida["filas"] = filas
    salida["conteo"] = {c: sum(1 for f in filas if f["clase"] == c) for c in CLASES}
    dias = salida.get("dias_con_datos") or 0
    faltan = []
    if dias < MIN_DIAS:
        faltan.append(f"{dias} días con datos (mínimo {MIN_DIAS})")
    if total < MIN_ABONADOS:
        faltan.append(f"{total} abonados activos (mínimo {MIN_ABONADOS})")
    salida["suficiente"] = not faltan
    salida["motivo_insuficiente"] = "; ".join(faltan) or None
    salida["percentiles"] = copy.deepcopy(percentiles or {})
    return salida


# ---------- propuesta .rsc ----------

_SIMBOLOS = {"≥": ">=", "≤": "<=", "—": "-", "–": "-", "×": "x", "→": "->", "…": "..."}


def _solo_ascii(texto):
    """ASCII puro (acentos sin tilde, símbolos por su equivalente): /import de RouterOS 6.49 puede fallar con UTF-8."""
    texto = str(texto)
    for simbolo, equivalente in _SIMBOLOS.items():
        texto = texto.replace(simbolo, equivalente)
    return unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()


def _ascii(texto):
    """Comentarios de reglas en ASCII y sin caracteres que RouterOS interpreta dentro de "..." ($, \\, ")."""
    return re.sub(r'["\\$]', "", _solo_ascii(texto))


def _nombre_lista(texto):
    return re.sub(r"[^A-Z0-9-]", "", _ascii(texto).upper().replace("_", "-")) or "CAT"


def _evidencia(f):
    return (f"evidencia: {f.get('abonados', 0)} abonados, {_texto_pct(f.get('pct_decision', 0))} %, "
            f"{f.get('flujos', 0)} flujos, {f.get('dias_observado', 0)} d")


def _pareja(p, f, comentado=False, nota=None):
    """Regla de detección + drop gemelo desactivado para una fila de riesgo."""
    entrante = f["sentido"] == "entrante"
    cadena = f"{p}-ENTRADA" if entrante else f"{p}-SALIDA"
    desde, hasta = _rango(f)
    puertos = str(desde) if desde == hasta else f"{desde}-{hasta}"
    sufijo = f.get("proto", "").upper() + puertos
    lista = f"DET-{p}-ENT-{sufijo}" if entrante else f"DET-{p}-{sufijo}"
    accion = "add-dst-to-address-list" if entrante else "add-src-to-address-list"
    match = f"protocol={f['proto']} dst-port={puertos}"
    servicio = f.get("servicio") or f.get("etiqueta")
    det = (f"add chain={cadena} action={accion} address-list={lista} address-list-timeout=1d {match} "
           f'comment="{_ascii(p + ": " + str(servicio) + " " + f["sentido"] + " (" + (nota or _evidencia(f)) + ")")}"')
    drop = (f"add chain={cadena} action=drop {match} disabled=yes "
            f'comment="{_ascii(p + ": " + str(servicio) + " " + f["sentido"] + " DROP (activar tras revision)")}"')
    return ["# " + det, "# " + drop] if comentado else [det, drop]


def propuesta_rsc(clasificacion, percentiles, prefijo=None, lista=None, limite_conexiones=None, fecha=None):
    """Texto .rsc de la capa de categoría, en modo detección, en ASCII puro. Determinista: misma entrada, mismo texto."""
    cat = str(clasificacion.get("categoria") or "categoria")
    p = _nombre_lista(prefijo or _PREFIJOS.get(cat, cat))
    lista = _nombre_lista(lista or "CAT-" + cat)
    filas = clasificacion.get("filas", [])
    conteo = clasificacion.get("conteo") or {c: sum(1 for f in filas if f.get("clase") == c) for c in CLASES}
    routers = ", ".join(clasificacion.get("routers") or []) or "todos los routers"
    L = [f"# Propuesta firewall {cat} — mikrotik-traffic-profiler (NetFlow)"]
    if fecha:
        L.append(f"# Generada: {fecha}")
    L.append(f"# Evidencia: {routers}, {clasificacion.get('desde') or '?'}..{clasificacion.get('hasta') or '?'} "
             f"({clasificacion.get('dias_con_datos') or 0} días), {clasificacion.get('abonados_total') or 0} abonados activos.")
    if not clasificacion.get("suficiente", False):
        L.append(f"# ATENCIÓN: evidencia insuficiente ({clasificacion.get('motivo_insuficiente') or 'sin datos'}). "
                 "Generada a pedido: no aplicar sin más datos.")
    L.append("# Clasificación: " + ", ".join(f"{c.replace('_', ' ')} {conteo.get(c, 0)}" for c in CLASES) + ".")
    esenciales = [f["etiqueta"] + ("" if f.get("sentido") == "saliente" else " " + f["sentido"])
                  for f in filas if f.get("clase") == "esencial"]
    if esenciales:
        L.append("# No se tocan (esenciales): " + ", ".join(esenciales[:40]) + (" …" if len(esenciales) > 40 else ""))
    L += [f"# MODO DETECCIÓN: cada regla añade a una lista DET-{p}-*; el drop gemelo va disabled=yes.",
          "# Solo conexiones nuevas (connection-state=new): no corta sesiones vivas ni toca FastTrack.",
          "# Despliegue: respaldo (/system backup save + /export) → Safe Mode → UN core canario → "
          "revisar contadores 7 días → activar drops → flota.",
          "# Los dos jump de forward van después de accept established,related (moverlos con place-before).",
          "/ip firewall address-list",
          f'# add list={lista} address=<rango {cat}> comment="{_ascii(p + ": rango " + cat)}"',
          "/ip firewall filter",
          f'add chain=forward action=jump jump-target={p}-SALIDA src-address-list={lista} connection-state=new comment="{p}: capa salida"',
          f'add chain=forward action=jump jump-target={p}-ENTRADA dst-address-list={lista} connection-state=new comment="{p}: capa entrada"',
          f'add chain={p}-SALIDA action=return src-address-list={p}-EXCEPCION comment="{p}: excepciones por abonado"']

    riesgo = [f for f in filas if f.get("clase") == "riesgo"]
    previos = [f for f in filas if f.get("clase") == "no_observado" and f.get("riesgo")]
    for sentido in ("saliente", "entrante"):
        bloque = []
        for f in riesgo:
            if f.get("sentido") == sentido and not f.get("revisar"):
                bloque += _pareja(p, f)
        for f in riesgo:
            if f.get("sentido") == sentido and f.get("revisar"):
                bloque.append(f"# masivo: decidir a mano — {f['etiqueta']} {sentido} ({_evidencia(f)})")
                bloque += _pareja(p, f, comentado=True)
        sin = [f for f in previos if f.get("sentido") == sentido]
        if sin:
            bloque.append(f"# Bloqueo preventivo opcional ({sentido}, riesgo conocido no observado en el periodo):")
            for f in sin:
                bloque += _pareja(p, f, comentado=True, nota="no observado en el periodo")
        if sentido == "saliente":
            L += bloque
            L += _limites(p, percentiles, limite_conexiones)
            L.append(f'add chain={p}-SALIDA action=return comment="{p}: fin capa salida"')
            L.append(f'add chain={p}-ENTRADA action=accept connection-nat-state=dstnat comment="{p}: port-forwards contratados"')
        else:
            L += bloque
    L += [f"add chain={p}-ENTRADA action=add-dst-to-address-list address-list=DET-{p}-ENTRANTE address-list-timeout=1d "
          f'comment="{p}: entrante nuevo sin dst-nat"',
          f'add chain={p}-ENTRADA action=drop disabled=yes comment="{p}: entrante DROP (activar tras revision)"',
          f'# Rollback: /ip firewall filter remove [find comment~"^{p}:"]',
          f'#           /ip firewall address-list remove [find list~"^DET-{p}-"]']
    return _solo_ascii("\n".join(L) + "\n")  # todo el archivo en ASCII, cabecera incluida


def _limites(p, percentiles, limite_conexiones):
    """Ráfaga de conexiones nuevas (dst-limit = 2 × p99.9 de tcp_nuevas por minuto) y, opcional, connection-limit."""
    L = []
    p999 = (percentiles or {}).get("tcp_nuevas", {}).get("p99.9")
    if isinstance(p999, (int, float)) and p999 > 0:
        n = math.ceil(2 * p999)
        L += [f'add chain={p}-SALIDA action=jump jump-target={p}-RAFAGA protocol=tcp tcp-flags=syn comment="{p}: rafaga de conexiones nuevas"',
              f"add chain={p}-RAFAGA action=return dst-limit={n}/1m,{n},src-address/5m "
              f'comment="{p}: limite = 2 x p99.9 tcp_nuevas por minuto ({p999:g})"',
              f"add chain={p}-RAFAGA action=add-src-to-address-list address-list=DET-{p}-RAFAGA address-list-timeout=1d "
              f'comment="{p}: excede rafaga"',
              f'add chain={p}-RAFAGA action=drop disabled=yes comment="{p}: rafaga DROP (activar tras revision)"']
    else:
        L.append("# Sin percentiles NetFlow de tcp_nuevas: no se propone límite de ráfaga (dst-limit).")
    if limite_conexiones:
        n = int(limite_conexiones)
        L += [f"add chain={p}-SALIDA action=add-src-to-address-list address-list=DET-{p}-CONEX address-list-timeout=1d "
              f'protocol=tcp connection-limit={n},32 comment="{p}: mas de {n} conexiones TCP simultaneas (2 x p99.9 conntrack)"',
              f'add chain={p}-SALIDA action=drop protocol=tcp connection-limit={n},32 disabled=yes '
              f'comment="{p}: conexiones DROP (activar tras revision)"']
    else:
        L.append("# connection-limit: sale del p99.9 de conntrack (concurrencia), no de NetFlow; pasar --limite-conexiones N.")
    return L


# ---------- CLI ----------

def main(argv=None, db=None):
    a = argparse.ArgumentParser(description="Clasifica los servicios de una categoría (NetFlow) y genera la propuesta .rsc.")
    a.add_argument("--datos", required=True, type=Path)
    a.add_argument("--categoria", required=True)
    a.add_argument("--router")
    a.add_argument("--dias", type=int, default=7)
    a.add_argument("--salida", type=Path)
    a.add_argument("--forzar", action="store_true", help="generar aunque la evidencia sea insuficiente")
    a.add_argument("--limite-conexiones", type=int, help="connection-limit por abonado (2 × p99.9 de conntrack)")
    a.add_argument("--fecha", help="fecha de la cabecera (por defecto, hoy)")
    args = a.parse_args(argv)
    if db is None:
        from . import flujos_db as db
    try:
        con = db.abrir(args.datos / getattr(db, "RUTA_RELATIVA", "flujos.db"), solo_lectura=True)
    except FileNotFoundError:
        print(f"no hay base NetFlow en {args.datos}", file=sys.stderr)
        return 2
    try:
        serv = db.servicios_categoria(con, args.categoria, args.router, args.dias)
        perc = db.percentiles_abonado(con, args.categoria, args.router, "7d")
    except ValueError as err:
        print(f"consulta inválida: {err}", file=sys.stderr)
        return 2
    finally:
        con.close()
    cl = clasificar(serv, perc)
    if not cl["suficiente"] and not args.forzar:
        print(f"evidencia insuficiente: {cl['motivo_insuficiente']} (usar --forzar para generarla igual)", file=sys.stderr)
        return 1
    texto = propuesta_rsc(cl, perc, limite_conexiones=args.limite_conexiones, fecha=args.fecha or date.today().isoformat())
    if args.salida:
        args.salida.write_text(texto, encoding="utf-8")
        print(f"propuesta en {args.salida}", file=sys.stderr)
    elif hasattr(sys.stdout, "buffer"):
        sys.stdout.buffer.write(texto.encode("utf-8"))
        sys.stdout.flush()
    else:
        sys.stdout.write(texto)
    return 0


if __name__ == "__main__":
    sys.exit(main())
