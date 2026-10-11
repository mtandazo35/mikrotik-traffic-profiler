#!/usr/bin/env python3
"""Imita a nfdump en las pruebas (en Windows no hay nfdump). El "archivo nfcapd" es texto con líneas CSV.

  nfdump_falso.py -I -r X          imprime X.stat si existe; si no, "Flows: <líneas>" y "Bytes: <suma>"
  nfdump_falso.py -r X -q -N -o csv:… "net A or net B"
                                   imprime la cabecera y las líneas de X que cumplen el filtro (las que no se
                                   pueden decidir, como IPv6, pasan: así se prueba que el procesador las omite)
En X: la línea "#ERROR" corta la salida y sale con 255 (archivo truncado); "#DORMIR n" duerme n segundos.
"""
import ipaddress
import sys
import time

CABECERA = "proto,srcAddr,srcPort,dstAddr,dstPort,flags,inPackets,inBytes,flows,input,output"


def _bytes(linea):
    partes = linea.split(",")
    return int(partes[7]) if len(partes) == 11 and partes[7].isdigit() else 0


def _cumple(linea, redes):
    partes = linea.split(",")
    try:
        src, dst = ipaddress.ip_address(partes[1]), ipaddress.ip_address(partes[3])
    except (IndexError, ValueError):
        return True
    if src.version != 4 or dst.version != 4:
        return True
    return any(src in r or dst in r for r in redes)


def main(argv):
    archivo, info, filtro = None, False, ""
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "-r":
            archivo = argv[i + 1]
            i += 2
            continue
        if a in ("-o", "-M", "-R", "-t"):
            i += 2
            continue
        if a == "-I":
            info = True
        elif not a.startswith("-"):
            filtro = a
        i += 1
    if not archivo:
        print("nfdump_falso: falta -r", file=sys.stderr)
        return 254
    try:
        with open(archivo, encoding="utf-8") as f:
            lineas = f.read().splitlines()
    except OSError as e:
        print(f"nfdump_falso: {e}", file=sys.stderr)
        return 255
    if info:
        try:
            with open(archivo + ".stat", encoding="utf-8") as f:
                print(f.read(), end="")
        except FileNotFoundError:
            datos = [x for x in lineas if x and not x.startswith("#")]
            print(f"Ident: falso\nFlows: {len(datos)}\nBytes: {sum(_bytes(x) for x in datos)}\n"
                  f"Sequence failures: 0")
        return 0
    redes = [ipaddress.ip_network(t, strict=False) for t in filtro.split() if "/" in t]  # "net A or net B"
    print(CABECERA, flush=True)
    for linea in lineas:
        if linea == "#ERROR":
            sys.stdout.flush()
            print("nfdump_falso: archivo truncado (Unexpected end of file)", file=sys.stderr)
            return 255
        if linea.startswith("#DORMIR"):
            sys.stdout.flush()
            time.sleep(float(linea.split()[1]))
            continue
        if not linea or linea.startswith("#"):
            continue
        if not redes or _cumple(linea, redes):
            print(linea)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
