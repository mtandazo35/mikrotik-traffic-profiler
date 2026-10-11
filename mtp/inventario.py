"""Inventario de routers: lectura, validación de altas desde el panel y guardado atómico."""
import ipaddress
import json
import os
import re
import tempfile
from pathlib import Path

NOMBRE = re.compile(r"^[a-z0-9][a-z0-9-]{0,39}$")
HOST = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$")
USUARIO = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
CATEGORIAS = ("residencial", "empresarial")
VACIO = {"maximo_conexiones_por_cidr": 150000, "routers": {}}


def leer(ruta):
    try:
        inv = json.loads(Path(ruta).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return json.loads(json.dumps(VACIO))
    inv.setdefault("routers", {})
    return inv


def guardar(ruta, inv):
    """Escribe en un temporal de la misma carpeta y lo renombra: nunca queda un JSON a medias."""
    ruta = Path(ruta)
    fd, tmp = tempfile.mkstemp(dir=ruta.parent, prefix=".inventario-", suffix=".json")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(inv, f, ensure_ascii=False, indent=2)
            f.write("\n")
        os.chmod(tmp, 0o640)
        os.replace(tmp, ruta)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise


def _cidrs(texto, categoria):
    redes = []
    for trozo in re.split(r"[\s,;]+", texto or ""):
        if not trozo:
            continue
        try:
            red = ipaddress.ip_network(trozo, strict=False)
        except ValueError:
            raise ValueError(f"{categoria}: «{trozo}» no es un rango válido (ejemplo 100.64.0.0/22)")
        if red.version != 4 or red.prefixlen < 8:
            raise ValueError(f"{categoria}: «{trozo}» debe ser IPv4 de /8 a /32")
        redes.append(red)
    return redes


def router_desde_form(f):
    """(nombre, router) validados a partir del formulario del panel. ValueError con un mensaje legible."""
    nombre = (f.get("nombre") or "").strip().lower()
    if not NOMBRE.match(nombre):
        raise ValueError("Nombre: minúsculas, números y guiones (máx. 40), p. ej. «core-centro».")
    host = (f.get("host") or "").strip()
    if not HOST.match(host):
        raise ValueError("IP o nombre del router inválido.")
    try:
        puerto = int(f.get("puerto") or 22)
    except ValueError:
        raise ValueError("Puerto SSH inválido.")
    if not 1 <= puerto <= 65535:
        raise ValueError("Puerto SSH fuera de rango (1-65535).")
    usuario = (f.get("usuario") or "trafico").strip()
    if not USUARIO.match(usuario):
        raise ValueError("Usuario inválido.")
    exportador = (f.get("exportador") or "").strip()
    if exportador:
        try:
            exportador = str(ipaddress.IPv4Address(exportador))
        except ValueError:
            raise ValueError("IP de exportación NetFlow inválida (debe ser IPv4).")

    categorias, todas = {}, []
    for cat in CATEGORIAS:
        redes = _cidrs(f.get(cat), cat)
        if redes:
            categorias[cat] = [str(r) for r in redes]
            todas += [(cat, r) for r in redes]
    if not todas:
        raise ValueError("Falta al menos un rango de clientes (residencial o empresarial).")
    for i, (cat_a, a) in enumerate(todas):
        for cat_b, b in todas[i + 1:]:
            if a.overlaps(b):
                raise ValueError(f"Rangos solapados: {a} ({cat_a}) y {b} ({cat_b}).")

    router = {"host": host, "puerto": puerto, "usuario": usuario, "transporte": "ssh",
              "categorias": categorias, "activo": f.get("activo") == "on"}
    if exportador:
        router["exportador"] = exportador
    return nombre, router
