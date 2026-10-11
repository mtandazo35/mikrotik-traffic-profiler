#!/usr/bin/env python3
"""mikrotik-traffic-profiler — CLI.

  python trafico.py descubrir  --router NOMBRE
  python trafico.py contar     --router NOMBRE --categoria residencial
  python trafico.py recolectar --router NOMBRE --categoria residencial [--repetir 4 --intervalo 15]
  python trafico.py recolectar-todos [--repetir 4 --intervalo 15]   # routers con "activo": true, todas sus categorías
  python trafico.py probar     --router NOMBRE                       # identidad y versión (comprueba el acceso)
  python trafico.py analizar   [--categoria residencial] [--router A] [--ip2asn data/ip2asn-v4.tsv.gz] [--dias 7]
  python trafico.py limpiar    [--dias 14]    # retención: borra crudo y logs viejos, conserva informes
  python trafico.py asn        [--dias 7]     # descarga/refresca data/ip2asn-v4.tsv.gz (iptoasn.com)
"""
import argparse
import json
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
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

    t = sub.add_parser("recolectar-todos", help="muestrear todos los routers activos del inventario")
    t.add_argument("--repetir", type=int, default=1)
    t.add_argument("--intervalo", type=float, default=15, help="minutos entre repeticiones")

    pr = sub.add_parser("probar", help="comprobar el acceso SSH (identidad y versión)")
    pr.add_argument("--router", required=True)

    a = sub.add_parser("analizar", help="perfil por categoría a partir de las muestras")
    a.add_argument("--categoria", help="por defecto, todas las que tengan muestras")
    a.add_argument("--router", action="append")
    a.add_argument("--ip2asn", type=Path, help="TSV de iptoasn.com (ip2asn-v4.tsv.gz)")
    a.add_argument("--dias", type=float, help="solo muestras de los últimos N días (por defecto, todas)")

    lm = sub.add_parser("limpiar", help="borrar muestras crudas y logs de más de N días (los informes quedan)")
    lm.add_argument("--dias", type=float, default=14)

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
        # iptoasn.com responde 403 al User-Agent por defecto de urllib
        pedido = urllib.request.Request(URL_IP2ASN, headers={"User-Agent": "mikrotik-traffic-profiler/1.0"})
        with urllib.request.urlopen(pedido, timeout=120) as r, temporal.open("wb") as f:
            f.write(r.read())
        temporal.replace(destino)
        print(f"{destino} descargado ({destino.stat().st_size // 1024} KiB)")
        return

    if args.orden == "limpiar":
        print(f"{analizar.limpiar(args.datos, args.dias)} muestras borradas (más de {args.dias:g} días)")
        return

    if args.orden == "analizar":
        asn = None
        if args.ip2asn and args.ip2asn.exists():
            asn = analizar.Asn(args.ip2asn)
        elif args.ip2asn:
            print(f"aviso: no existe {args.ip2asn}; destinos agrupados por /16", file=sys.stderr)
        categorias = [args.categoria] if args.categoria else analizar.categorias(args.datos)
        hechos = 0
        for categoria in categorias:
            perfil = analizar.analizar(args.datos, categoria, args.router, asn, args.dias)
            if perfil["resumen"]["muestras"]:
                print(analizar.guardar(perfil, args.datos))
                hechos += 1
        if not hechos:
            sys.exit(f"no hay muestras de {', '.join(categorias) or 'ninguna categoría'} en {args.datos / 'crudo'}")
        return

    inv = _inventario(args.inventario)
    if args.orden == "recolectar-todos":
        maximo = inv.get("maximo_conexiones_por_cidr", 150000)
        activos = {n: r for n, r in inv["routers"].items() if r.get("activo")}
        if not activos:
            print("ningún router con muestreo activo")
            return

        def un_router(nombre, rt):
            for categoria in rt.get("categorias", {}):
                for m in mk.muestrear(rt, nombre, categoria, args.datos, maximo):
                    print(json.dumps(m, ensure_ascii=False), flush=True)

        fallos = 0
        for i in range(args.repetir):
            if i:
                time.sleep(args.intervalo * 60)
            with ThreadPoolExecutor(max_workers=8) as pool:
                trabajos = {pool.submit(un_router, n, r): n for n, r in activos.items()}
                for t in as_completed(trabajos):
                    if t.exception():
                        fallos += 1
                        print(f"{trabajos[t]}: {t.exception()}", file=sys.stderr, flush=True)
        sys.exit(1 if fallos else 0)

    rt = _router(inv, args.router)
    if args.orden == "probar":
        print(mk.probar(rt))
    elif args.orden == "descubrir":
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
