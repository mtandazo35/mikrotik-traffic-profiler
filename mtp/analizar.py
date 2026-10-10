"""Perfil de tráfico de una categoría a partir de las muestras de conntrack guardadas."""
import bisect
import math
import gzip
import ipaddress
import json
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from . import servicios
from .conntrack import clasificar, leer

# Puertos que, vistos en abonados residenciales, merecen revisión aunque sean pocos.
_SENSIBLES_SALIENTES = {("tcp", 25), ("tcp", 23), ("tcp", 2323), ("tcp", 445), ("tcp", 139), ("tcp", 135),
                        ("udp", 137), ("udp", 138), ("tcp", 3389), ("tcp", 5900), ("tcp", 7547)}
_REFLECTORES = {53, 123, 1900, 11211, 19, 389, 161, 5353}
_UMBRAL_BARRIDO = 50  # destinos distintos al mismo puerto en una sola muestra


class Asn:
    """Búsqueda IP→ASN con el TSV de iptoasn.com (ip2asn-v4.tsv[.gz]), sin servicios externos."""

    def __init__(self, ruta):
        abrir = gzip.open if str(ruta).endswith(".gz") else open
        self.inicios, self.finales, self.datos = [], [], []
        with abrir(ruta, "rt", encoding="utf-8", errors="replace") as f:
            for linea in f:
                partes = linea.rstrip("\n").split("\t")
                if len(partes) < 5 or partes[2] == "0":
                    continue
                self.inicios.append(int(ipaddress.IPv4Address(partes[0])))
                self.finales.append(int(ipaddress.IPv4Address(partes[1])))
                self.datos.append(f"AS{partes[2]} {partes[4]} ({partes[3]})")

    def __call__(self, ip):
        n = int(ip)
        i = bisect.bisect_right(self.inicios, n) - 1
        return self.datos[i] if i >= 0 and n <= self.finales[i] else "sin ASN"


def _por_prefijo16(ip):
    return str(ipaddress.ip_network(f"{ip}/16", strict=False))


def percentiles(valores, puntos=(50, 90, 99, 99.9)):
    if not valores:
        return {}
    v = sorted(valores)
    salida = {f"p{p:g}": v[min(len(v), max(1, math.ceil(p / 100 * len(v)))) - 1] for p in puntos}
    salida["max"] = v[-1]
    return salida


def muestras(datos, categoria, routers=None):
    """(router, ts, cidr, ruta) de cada muestra válida del manifiesto."""
    for manifiesto in sorted(Path(datos, "crudo").glob(f"*/{categoria}/muestras.jsonl")):
        router = manifiesto.parent.parent.name
        if routers and router not in routers:
            continue
        for linea in manifiesto.read_text(encoding="utf-8").splitlines():
            m = json.loads(linea)
            if m.get("archivo"):
                yield router, m["ts"], m["cidr"], manifiesto.parent / m["archivo"]


def _nuevo():
    return {"conexiones": 0, "abonados": set(), "bytes": 0}


def analizar(datos, categoria, routers=None, asn=None):
    destino_de = asn or _por_prefijo16
    salientes = defaultdict(_nuevo)
    entrantes = defaultdict(_nuevo)
    destinos = defaultdict(_nuevo)
    por_router = defaultdict(lambda: {"muestras": 0, "abonados": set(), "conexiones": 0})
    por_abonado = []  # una fila por (muestra, abonado)
    senales = defaultdict(lambda: defaultdict(lambda: {"conexiones": 0, "destinos": set()}))
    barridos = []
    horas = set()
    total = 0
    abonados_total = set()

    for router, ts, cidr, ruta in muestras(datos, categoria, routers):
        redes = [ipaddress.ip_network(cidr, strict=False)]
        horas.add(ts[9:11])
        por_router[router]["muestras"] += 1
        en_muestra = defaultdict(lambda: {"conexiones": 0, "udp": 0, "puertos": set(), "ips": set(), "syn": 0})
        destinos_por_puerto = defaultdict(set)
        for con in leer(ruta.read_text(encoding="utf-8")):
            c = clasificar(con, redes)
            if not c:
                continue
            sentido, abonado, puerto = c
            total += 1
            bytes_ = con.bytes_ida + con.bytes_vuelta
            abonados_total.add(abonado)
            por_router[router]["abonados"].add(abonado)
            por_router[router]["conexiones"] += 1
            if sentido == "entrante":
                fila = entrantes[(con.proto, puerto)]
            elif sentido == "saliente":
                fila = salientes[(con.proto, puerto)]
                d = destinos[destino_de(con.dst)]
                d["conexiones"] += 1
                d["abonados"].add(abonado)
                d["bytes"] += bytes_
                a = en_muestra[abonado]
                a["conexiones"] += 1
                a["udp"] += con.proto == "udp"
                a["syn"] += con.estado_tcp == "syn-sent"
                if puerto is not None:
                    a["puertos"].add((con.proto, puerto))
                a["ips"].add(con.dst)
                destinos_por_puerto[(abonado, con.proto, puerto)].add(con.dst)
                if (con.proto, puerto) in _SENSIBLES_SALIENTES:
                    s = senales[f"{con.proto}/{puerto} {servicios.nombre(con.proto, puerto)}"][str(abonado)]
                    s["conexiones"] += 1
                    s["destinos"].add(con.dst)
            else:
                continue
            fila["conexiones"] += 1
            fila["abonados"].add(abonado)
            fila["bytes"] += bytes_
            if sentido == "entrante" and con.proto == "udp" and puerto in _REFLECTORES:
                s = senales[f"udp/{puerto} entrante (posible reflector)"][str(abonado)]
                s["conexiones"] += 1
                s["destinos"].add(con.src)

        for (abonado, proto, puerto), ips in destinos_por_puerto.items():
            if len(ips) >= _UMBRAL_BARRIDO and (proto, puerto) not in {("tcp", 443), ("udp", 443), ("tcp", 80)}:
                barridos.append({"router": router, "muestra": ts, "abonado": str(abonado),
                                 "puerto": f"{proto}/{puerto}", "servicio": servicios.nombre(proto, puerto),
                                 "destinos_distintos": len(ips)})
        for a in en_muestra.values():
            por_abonado.append({"conexiones": a["conexiones"], "udp": a["udp"], "puertos": len(a["puertos"]),
                                "ips": len(a["ips"]), "syn": a["syn"]})

    n_abonados = len(abonados_total) or 1

    def tabla(origen, limite):
        filas = []
        for (proto, puerto), v in sorted(origen.items(), key=lambda kv: -len(kv[1]["abonados"])):
            filas.append({"proto": proto, "puerto": puerto, "servicio": servicios.nombre(proto, puerto),
                          "abonados": len(v["abonados"]), "pct_abonados": round(100 * len(v["abonados"]) / n_abonados, 1),
                          "conexiones": v["conexiones"], "bytes": v["bytes"]})
        return filas[:limite]

    return {
        "categoria": categoria,
        "generado": datetime.now().isoformat(timespec="seconds"),
        "resumen": {
            "routers": sorted(por_router),
            "muestras": sum(r["muestras"] for r in por_router.values()),
            "horas_muestreadas": sorted(horas),
            "abonados_observados": len(abonados_total),
            "conexiones_analizadas": total,
            "destinos_agrupados_por": "ASN" if asn else "prefijo /16 (sin ip2asn)",
        },
        "salientes": tabla(salientes, 80),
        "entrantes": tabla(entrantes, 40),
        "destinos": [
            {"destino": k, "abonados": len(v["abonados"]),
             "pct_abonados": round(100 * len(v["abonados"]) / n_abonados, 1),
             "conexiones": v["conexiones"], "bytes": v["bytes"]}
            for k, v in sorted(destinos.items(), key=lambda kv: -len(kv[1]["abonados"]))[:50]
        ],
        "por_abonado": {campo: percentiles([f[campo] for f in por_abonado])
                        for campo in ("conexiones", "udp", "puertos", "ips", "syn")},
        "senales": {
            nombre_senal: sorted(({"abonado": ab, "conexiones": v["conexiones"], "destinos_distintos": len(v["destinos"])}
                                  for ab, v in filas.items()), key=lambda f: -f["conexiones"])
            for nombre_senal, filas in sorted(senales.items())
        },
        "barridos": sorted(barridos, key=lambda b: -b["destinos_distintos"])[:50],
        "por_router": {r: {"muestras": v["muestras"], "abonados": len(v["abonados"]), "conexiones": v["conexiones"]}
                       for r, v in sorted(por_router.items())},
    }


def _bytes(n):
    for unidad in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {unidad}"
        n /= 1024
    return f"{n:.0f} PiB"


def markdown(p):
    r = p["resumen"]
    out = [
        f"# Perfil de tráfico — {p['categoria']}",
        "",
        f"Generado {p['generado']}. Routers: {', '.join(r['routers']) or '—'}. Muestras: {r['muestras']}. "
        f"Horas muestreadas: {', '.join(r['horas_muestreadas']) or '—'}. Abonados observados: {r['abonados_observados']}. "
        f"Conexiones analizadas: {r['conexiones_analizadas']}. Destinos agrupados por {r['destinos_agrupados_por']}.",
        "",
        "> Los bytes son orientativos: con FastTrack por hardware (hw-offload) el contador de conntrack no avanza. "
        "Conexiones y abonados distintos sí son fiables. Cada muestra es una foto: lo que dura poco (DNS, NTP) "
        "aparece menos de lo que pesa.",
        "",
        "## Servicios salientes (ordenados por % de abonados que los usan)",
        "",
        "| Proto/puerto | Servicio | % abonados | Abonados | Conexiones | Bytes |",
        "|---|---|---:|---:|---:|---:|",
    ]
    for f in p["salientes"]:
        out.append(f"| {f['proto']}/{f['puerto'] if f['puerto'] is not None else '-'} | {f['servicio']} | "
                   f"{f['pct_abonados']} | {f['abonados']} | {f['conexiones']} | {_bytes(f['bytes'])} |")
    out += ["", "## Conexiones entrantes hacia abonados", "",
            "| Proto/puerto | Servicio | % abonados | Abonados | Conexiones |", "|---|---|---:|---:|---:|"]
    for f in p["entrantes"]:
        out.append(f"| {f['proto']}/{f['puerto'] if f['puerto'] is not None else '-'} | {f['servicio']} | "
                   f"{f['pct_abonados']} | {f['abonados']} | {f['conexiones']} |")
    if not p["entrantes"]:
        out.append("| — | sin conexiones entrantes en las muestras | | | |")
    out += ["", "## Destinos", "", "| Destino | % abonados | Conexiones | Bytes |", "|---|---:|---:|---:|"]
    for f in p["destinos"]:
        out.append(f"| {f['destino']} | {f['pct_abonados']} | {f['conexiones']} | {_bytes(f['bytes'])} |")
    out += ["", "## Por abonado y muestra (base para límites)", "",
            "| Métrica | p50 | p90 | p99 | p99.9 | máx |", "|---|---:|---:|---:|---:|---:|"]
    etiquetas = {"conexiones": "Conexiones salientes", "udp": "Conexiones UDP", "puertos": "Puertos destino distintos",
                 "ips": "IP destino distintas", "syn": "TCP en syn-sent (sin respuesta)"}
    for campo, texto in etiquetas.items():
        v = p["por_abonado"].get(campo, {})
        out.append(f"| {texto} | {v.get('p50', '-')} | {v.get('p90', '-')} | {v.get('p99', '-')} | "
                   f"{v.get('p99.9', '-')} | {v.get('max', '-')} |")
    out += ["", "## Señales a revisar", ""]
    if not p["senales"] and not p["barridos"]:
        out.append("Sin señales en las muestras.")
    for nombre_senal, filas in p["senales"].items():
        out.append(f"- **{nombre_senal}**: {len(filas)} abonados. Mayores: " + ", ".join(
            f"{f['abonado']} ({f['conexiones']} conex., {f['destinos_distintos']} destinos)" for f in filas[:5]))
    for b in p["barridos"][:15]:
        out.append(f"- Barrido: {b['abonado']} en {b['router']} ({b['muestra']}) → {b['puerto']} {b['servicio']} "
                   f"hacia {b['destinos_distintos']} destinos distintos")
    out += ["", "## Por router", "", "| Router | Muestras | Abonados | Conexiones |", "|---|---:|---:|---:|"]
    for nombre_router, v in p["por_router"].items():
        out.append(f"| {nombre_router} | {v['muestras']} | {v['abonados']} | {v['conexiones']} |")
    return "\n".join(out) + "\n"


def guardar(perfil, datos):
    carpeta = Path(datos) / "informes"
    carpeta.mkdir(parents=True, exist_ok=True)
    base = carpeta / f"{perfil['categoria']}-{datetime.now():%Y%m%d-%H%M}"
    base.with_suffix(".json").write_text(json.dumps(perfil, ensure_ascii=False, indent=2), encoding="utf-8")
    base.with_suffix(".md").write_text(markdown(perfil), encoding="utf-8")
    return base.with_suffix(".md")
