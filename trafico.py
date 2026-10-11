#!/usr/bin/env python3
"""mikrotik-traffic-profiler — CLI.

  python trafico.py descubrir  --router NOMBRE
  python trafico.py contar     --router NOMBRE --categoria residencial
  python trafico.py recolectar --router NOMBRE --categoria residencial [--repetir 4 --intervalo 15]
  python trafico.py analizar   --categoria residencial [--router A --router B] [--ip2asn data/ip2asn-v4.tsv.gz]
  python trafico.py asn        [--dias 7]     # descarga/refresca data/ip2asn-v4.tsv.gz (iptoasn.com)
"""
import argparse
import json
import sys
import time
import urllib.request
from pathlib import Path

from mtp import analizar, router as mk

RAIZ = Path(__file__).resolve().parent
URL_IP2ASN = "https://iptoasn.com/data/ip2asn-v4.tsv.gz"


def _inventario(ruta):
    if not ruta.exists():
        sys.exit(f"no existe {ruta}: copiar inventario.example.json a inventario.json y completarlo")
    return json.loads(ruta.read_text(encoding="utf-8"))


def _router(inv, nombre):
    if nombre not in inv["routers"]:
        sys.exit(f"router {nombre!r} no está en el inventario ({', '.join(inv['routers'])})")
    return inv["routers"][nombre]


def main():
    p = argparse.ArgumentParser(description="Perfil de tráfico por categoría de abonado (solo lectura).")
    p.add_argument("--inventario", type=Path, default=RAIZ / "inventario.json")
    p.add_argument("--datos", type=Path, default=RAIZ / "data")
    sub = p.add_subparsers(dest="orden", required=True)

    d = sub.add_parser("descubrir", help="volcar pools, NAT, filtros y conntrack (solo print)")
    d.add_argument("--router", required=True)

    c = sub.add_parser("contar", help="conexiones por CIDR de la categoría, sin descargar nada")
    c.add_argument("--router", required=True)
    c.add_argument("--categoria", required=True)

    r = sub.add_parser("recolectar", help="guardar muestras de conntrack de la categoría")
    r.add_argument("--router", required=True)
    r.add_argument("--categoria", required=True)
    r.add_argument("--repetir", type=int, default=1)
    r.add_argument("--intervalo", type=float, default=15, help="minutos entre repeticiones")
    r.add_argument("--maximo", type=int, help="conexiones máximas por CIDR (por defecto, el del inventario)")

    a = sub.add_parser("analizar", help="perfil de la categoría a partir de las muestras")
    a.add_argument("--categoria", required=True)
    a.add_argument("--router", action="append")
    a.add_argument("--ip2asn", type=Path, help="TSV de iptoasn.com (ip2asn-v4.tsv.gz)")

    s = sub.add_parser("asn", help="descargar la tabla IP→ASN si falta o tiene más de N días")
    s.add_argument("--dias", type=float, default=7)

    args = p.parse_args()

    if args.orden == "asn":
        destino = args.datos / "ip2asn-v4.tsv.gz"
        if destino.exists() and time.time() - destino.stat().st_mtime < args.dias * 86400:
            print(f"{destino} al día")
            return
        destino.parent.mkdir(parents=True, exist_ok=True)
        temporal = destino.with_suffix(".parcial")
        with urllib.request.urlopen(URL_IP2ASN, timeout=120) as r, temporal.open("wb") as f:
            f.write(r.read())
        temporal.replace(destino)
        print(f"{destino} descargado ({destino.stat().st_size // 1024} KiB)")
        return

    if args.orden == "analizar":
        asn = None
        if args.ip2asn and args.ip2asn.exists():
            asn = analizar.Asn(args.ip2asn)
        elif args.ip2asn:
            print(f"aviso: no existe {args.ip2asn}; destinos agrupados por /16", file=sys.stderr)
        perfil = analizar.analizar(args.datos, args.categoria, args.router, asn)
        if not perfil["resumen"]["muestras"]:
            sys.exit(f"no hay muestras de {args.categoria!r} en {args.datos / 'crudo'}")
        print(analizar.guardar(perfil, args.datos))
        return

    inv = _inventario(args.inventario)
    rt = _router(inv, args.router)
    if args.orden == "descubrir":
        print(mk.descubrir(rt, args.router, args.datos))
    elif args.orden == "contar":
        for cidr in rt["categorias"][args.categoria]:
            print(f"{cidr}\t{mk.contar(rt, cidr)}")
    else:
        maximo = args.maximo or inv.get("maximo_conexiones_por_cidr", 150000)
        for m in mk.recolectar(rt, args.router, args.categoria, args.datos, maximo, args.repetir, args.intervalo):
            print(json.dumps(m, ensure_ascii=False))


if __name__ == "__main__":
    main()
