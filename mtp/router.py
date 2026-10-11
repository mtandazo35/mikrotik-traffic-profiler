"""Acceso SSH de solo lectura a RouterOS y recolección de muestras de conntrack.

Toda orden pasa por `comprobar_lectura`: si no es un `print` se rechaza antes de abrir SSH.
"""
import gzip
import json
import os
import re
import subprocess
import time
from datetime import datetime
from pathlib import Path

from .conntrack import regex_prefijo

_LECTURA = re.compile(r'^/[a-z0-9/ -]+ print(?: [^;\[\]{}]*)?$')  # sin ; ni [ ] = sin órdenes encadenadas
_VERBOS_PROHIBIDOS = {
    "add", "set", "remove", "unset", "enable", "disable", "reset", "reboot", "shutdown",
    "import", "export", "run", "execute", "fetch", "upgrade", "install", "flush",
    "reset-counters", "reset-configuration", "torch", "sniffer", "move", "comment",
}

DESCUBRIR = [
    "/system resource print",
    "/system routerboard print",
    "/system identity print",
    "/ip address print terse",
    "/ip pool print terse",
    "/interface list member print terse",
    "/ppp profile print terse",
    "/ppp active print count-only",
    "/ip dhcp-server print terse",
    "/ip firewall connection tracking print",
    "/ip firewall connection print count-only",
    "/ip firewall address-list print count-only",
    "/ip firewall raw print terse",
    "/ip firewall filter print terse",
    "/ip firewall nat print terse",
    "/ip firewall mangle print terse",
    "/queue simple print count-only",
    "/queue tree print count-only",
]


_CITA = re.compile(r'"([^"]*)"')
_CITA_OK = re.compile(r"^[0-9.^\[\]():|$]*$")  # solo regex de IP: sin letras no cabe ninguna orden


def comprobar_lectura(comando):
    citas = _CITA.findall(comando)
    sin_citas = _CITA.sub('""', comando)
    ruta = sin_citas.split(" print", 1)[0]
    if (not _LECTURA.match(sin_citas)
            or '"' in sin_citas.replace('""', "")
            or any(not _CITA_OK.match(c) or "$[" in c or "$(" in c for c in citas)
            or _VERBOS_PROHIBIDOS & set(re.split(r"[ /]+", ruta))):
        raise PermissionError(f"orden rechazada (solo se permite `print`): {comando}")


def ejecutar(router, comando, timeout=300):
    comprobar_lectura(comando)
    usuario = router["usuario"] + router.get("sufijo_usuario", "+ct")  # +c sin color, +t sin autodetección
    puerto = str(router.get("puerto", 22))
    entrada = None
    if router.get("transporte", "ssh") == "plink":
        clave = os.environ.get(router.get("password_env", ""), "")
        if not clave:
            raise SystemExit(f"falta la variable de entorno {router.get('password_env')!r} con la clave")
        cmd = ["plink", "-ssh", "-P", puerto, "-l", usuario, "-pw", clave, router["host"], comando]
        entrada = "y\n"  # acepta la host key: las IP se reutilizan en equipos nuevos
    else:
        cmd = [
            "ssh", "-o", "StrictHostKeyChecking=no", "-o", f"UserKnownHostsFile={os.devnull}",
            "-o", "BatchMode=yes", "-o", "ConnectTimeout=15", "-o", "LogLevel=ERROR",
            # RouterOS 6 solo habla ssh-rsa (SHA-1) y DH group14-sha1; OpenSSH moderno los trae apagados
            "-o", "HostKeyAlgorithms=+ssh-rsa", "-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
            "-o", "KexAlgorithms=+diffie-hellman-group14-sha1",
            "-p", puerto, f"{usuario}@{router['host']}", comando,
        ]
    r = subprocess.run(cmd, input=entrada, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace")
    if r.returncode != 0:
        raise RuntimeError(f"{router['host']}: `{comando}` salió con {r.returncode}: {r.stderr.strip()[-400:]}")
    return r.stdout


def _marca():
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def descubrir(router, nombre, datos):
    """Vuelca la configuración relevante (solo `print`) para ubicar pools, NAT y el punto de inserción."""
    destino = Path(datos) / "descubrimiento" / f"{nombre}-{_marca()}.txt"
    destino.parent.mkdir(parents=True, exist_ok=True)
    with destino.open("w", encoding="utf-8") as f:
        for comando in DESCUBRIR:
            f.write(f"\n### {comando}\n")
            try:
                f.write(ejecutar(router, comando))
            except (RuntimeError, subprocess.TimeoutExpired) as e:
                f.write(f"(error: {e})\n")
    return destino


def _filtro(cidr):
    rx = regex_prefijo(cidr)
    return f'where src-address~"{rx}" or dst-address~"{rx}" or reply-src-address~"{rx}"'


def contar(router, cidr):
    salida = ejecutar(router, f"/ip firewall connection print count-only {_filtro(cidr)}")
    m = re.search(r"\d+", salida)
    return int(m.group()) if m else 0


def muestrear(router, nombre, categoria, datos, maximo):
    """Una muestra de conntrack por cada CIDR de la categoría. Devuelve las entradas del manifiesto."""
    carpeta = Path(datos) / "crudo" / nombre / categoria
    carpeta.mkdir(parents=True, exist_ok=True)
    hechas = []
    for cidr in router["categorias"][categoria]:
        marca = _marca()
        n = contar(router, cidr)
        entrada = {"ts": marca, "router": nombre, "categoria": categoria, "cidr": cidr, "conexiones_router": n}
        if n > maximo:
            entrada["omitida"] = f"{n} conexiones > máximo {maximo}; partir el CIDR en trozos más chicos"
        else:
            archivo = carpeta / f"{marca}_{cidr.replace('/', '_')}.txt.gz"
            texto = ejecutar(router, f"/ip firewall connection print terse without-paging {_filtro(cidr)}")
            with gzip.open(archivo, "wt", encoding="utf-8") as f:  # ~10x menos disco
                f.write(texto)
            entrada["archivo"] = archivo.name
        with (carpeta / "muestras.jsonl").open("a", encoding="utf-8") as f:
            f.write(json.dumps(entrada, ensure_ascii=False) + "\n")
        hechas.append(entrada)
    return hechas


def recolectar(router, nombre, categoria, datos, maximo, repeticiones=1, intervalo_min=0):
    todas = []
    for i in range(repeticiones):
        if i:
            time.sleep(intervalo_min * 60)
        todas.extend(muestrear(router, nombre, categoria, datos, maximo))
    return todas
