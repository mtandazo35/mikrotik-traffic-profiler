"""Panel web: ver muestras, informes y actividad; lanzar acciones de solo lectura sobre los routers.

  python3 -m mtp.web --config /etc/mikrotik-traffic-profiler/web.json --inventario … --datos … [--puerto 8080]
  python3 -m mtp.web --config … --cambiar-clave          (lee la clave nueva de stdin)
"""
import argparse
import hashlib
import hmac
import html
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from datetime import date, datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlencode, urlparse

from . import firewall, inventario

RAIZ = Path(__file__).resolve().parent.parent
ITERACIONES = 600_000
SESION_HORAS = 8
CFG = {}
TAREAS = {}  # nombre de log -> Popen
_FALLOS = {}  # ip -> (fallos, bloqueado_hasta)
_CANDADO = threading.Lock()
FLUJOS = None  # módulo de consultas NetFlow (mtp.flujos_db); las pruebas ponen aquí uno falso


# ---------- credenciales y sesión ----------

def hash_clave(clave, iteraciones=ITERACIONES):
    sal = secrets.token_bytes(16)
    h = hashlib.pbkdf2_hmac("sha256", clave.encode(), sal, iteraciones)
    return f"pbkdf2_sha256${iteraciones}${sal.hex()}${h.hex()}"


def verificar_clave(clave, guardado):
    try:
        _, it, sal, h = guardado.split("$")
        calc = hashlib.pbkdf2_hmac("sha256", clave.encode(), bytes.fromhex(sal), int(it))
        return hmac.compare_digest(calc.hex(), h)
    except (ValueError, AttributeError):
        return False


def firmar(usuario, secreto, ahora=None):
    expira = int((ahora or time.time()) + SESION_HORAS * 3600)
    base = f"{usuario}|{expira}"
    return base + "|" + hmac.new(secreto.encode(), base.encode(), "sha256").hexdigest()


def sesion_valida(token, secreto, ahora=None):
    try:
        usuario, expira, firma = token.split("|")
    except (ValueError, AttributeError):
        return None
    esperada = hmac.new(secreto.encode(), f"{usuario}|{expira}".encode(), "sha256").hexdigest()
    if hmac.compare_digest(firma, esperada) and int(expira) > (ahora or time.time()):
        return usuario
    return None


def archivo_seguro(carpeta, nombre, patron=r"^[\w.-]+$"):
    """Solo nombres simples que existan dentro de la carpeta (sin rutas)."""
    if not nombre or not re.match(patron, nombre) or nombre.startswith("."):
        return None
    ruta = Path(carpeta) / nombre
    return ruta if ruta.is_file() and ruta.resolve().parent == Path(carpeta).resolve() else None


# ---------- datos ----------

def _inventario():
    try:
        return inventario.leer(CFG["inventario"])
    except (OSError, ValueError):
        return {"routers": {}}


def _datos(*partes):
    return Path(CFG["datos"], *partes)


def _manifiestos():
    filas = []
    for m in _datos("crudo").glob("*/*/muestras.jsonl"):
        for linea in m.read_text(encoding="utf-8").splitlines():
            try:
                filas.append(json.loads(linea))
            except ValueError:
                pass
    return sorted(filas, key=lambda f: f.get("ts", ""), reverse=True)


def _listar(carpeta, patron):
    c = _datos(carpeta)
    return sorted((p.name for p in c.glob(patron)), reverse=True) if c.is_dir() else []


def _flujos():
    """Módulo de consultas NetFlow, importado la primera vez. None si todavía no está instalado."""
    global FLUJOS
    if FLUJOS is None:
        try:
            from . import flujos_db
        except ImportError:
            return None
        FLUJOS = flujos_db
    return FLUJOS


def _abrir_flujos():
    """(módulo, conexión de solo lectura) o (módulo, None) si todavía no hay base NetFlow."""
    F = _flujos()
    if F is None:
        return None, None
    try:
        return F, F.abrir(_datos(getattr(F, "RUTA_RELATIVA", "flujos.db")), solo_lectura=True)
    except (OSError, sqlite3.Error):
        return F, None


def _timers():
    try:
        r = subprocess.run(["systemctl", "list-timers", "--all", "--no-pager", "mtp-*"],
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or "(sin timers)"
    except (OSError, subprocess.TimeoutExpired):
        return "(systemctl no disponible)"


def lanzar(accion, router=None, categoria=None):
    """Corre trafico.py en segundo plano con la salida en data/tareas/<marca>-<accion>-<router>.log."""
    with _CANDADO:
        for nombre, p in TAREAS.items():
            if p.poll() is None and (router or "todos") in nombre:
                return f"Ya hay una tarea en curso para {router or 'el análisis'}: {nombre}"
        cmd = [sys.executable, str(RAIZ / "trafico.py"), "--inventario", CFG["inventario"], "--datos", CFG["datos"], accion]
        if router:
            cmd += ["--router", router]
        if categoria:
            cmd += ["--categoria", categoria]
        if accion == "analizar":
            cmd += ["--ip2asn", str(_datos("ip2asn-v4.tsv.gz")), "--dias", "7"]
        _datos("tareas").mkdir(parents=True, exist_ok=True)
        nombre = f"{datetime.now():%Y%m%d-%H%M%S}-{accion}-{router or 'todos'}.log"
        log = _datos("tareas", nombre).open("w", encoding="utf-8")
        log.write(f"$ {' '.join(cmd[1:])}\n\n")
        log.flush()
        p = subprocess.Popen(cmd, stdout=log, stderr=subprocess.STDOUT, cwd=RAIZ)
        TAREAS[nombre] = p

        def _cerrar():
            rc = p.wait()
            log.write(f"\n[fin {datetime.now():%H:%M:%S}] código de salida {rc}\n")
            log.close()

        threading.Thread(target=_cerrar, daemon=True).start()
        return f"Tarea lanzada: {nombre}"


def ip_origen():
    """IP con la que este servidor sale a la red (no envía paquetes)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            return s.getsockname()[0]
    except OSError:
        return "IP_DE_ESTE_SERVIDOR"


def comandos_router(llave, ip):
    """Comandos para pegar en la terminal del MikroTik: (RouterOS 7, RouterOS 6, verificación, quitar)."""
    usuario = f'/user add name=trafico group=read address={ip}/32 comment="perfilador de trafico - solo lectura"'
    v7 = "\n".join([f'/file add name=trafico.pub contents="{llave}"', usuario,
                    "/user ssh-keys import user=trafico public-key-file=trafico.pub"])
    v6 = "\n".join(["/file print file=trafico", ":delay 2s", f'/file set trafico.txt contents="{llave}"', usuario,
                    "/user ssh-keys import user=trafico public-key-file=trafico.txt"])
    verificar = "\n".join(["/user print where name=trafico", "/user ssh-keys print", "/ip service print where name=ssh"])
    quitar = "\n".join(["/user ssh-keys remove [find user=trafico]", "/user remove [find name=trafico]"])
    return v7, v6, verificar, quitar


PUERTO_NETFLOW = 2055


def puerto_netflow():
    try:
        return int(os.environ.get("PUERTO_NETFLOW", PUERTO_NETFLOW))
    except ValueError:
        return PUERTO_NETFLOW


def interfaces_ros(texto):
    """Valor para interfaces=: nombres separados por coma, toda la lista entre comillas si alguno lleva espacios.
    None si está vacío o trae caracteres que RouterOS interpretaría dentro de una orden ("…", $, [], {}, ;, \\, =)."""
    nombres = [n.strip() for n in (texto or "").split(",") if n.strip()]
    if not nombres or any(len(n) > 64 or re.search(r'["$\[\]{};\\=#]', n) or not n.isprintable() for n in nombres):
        return None
    lista = ",".join(nombres)
    return f'"{lista}"' if " " in lista else lista


def comandos_netflow(ip, puerto=PUERTO_NETFLOW, ip_router=None, interfaces=None):
    """Script de Traffic Flow (NetFlow v9, igual en RouterOS 6.49 y 7): (mirar antes, activar, comprobar, quitar).

    ip = IP del colector (este servidor); ip_router = IP con la que este servidor ve al router (src-address);
    interfaces = interfaz(es) de clientes, separadas por coma. Lo que falte queda como marcador para reemplazar."""
    origen = ip_router or "IP_DEL_ROUTER"
    intf = interfaces_ros(interfaces) or "INTERFAZ-CLIENTES"
    primera = intf.strip('"').split(",")[0]
    primera = f'"{primera}"' if " " in primera else primera
    buscar = "\n".join([
        "# 0) ¿ya exporta a otro colector (otro sistema del ISP)? Mirar enabled, interfaces y los targets",
        "/ip traffic-flow print",
        "/ip traffic-flow target print",
        "# en qué interfaz están los gateways de los clientes (bridge o VLAN de clientes)",
        "/ip address print",
        "/interface bridge print",
        "/interface vlan print",
    ])
    activar = "\n".join([
        "# interfaces= es GLOBAL: vale para todos los colectores. Pegar el bloque entero (de { a }):",
        "# - traffic-flow apagado: lo activa con la interfaz de clientes y agrega el destino.",
        "# - ya activo (otro colector) con interfaces concretas: NO las cambia, las muestra y solo agrega el destino.",
        "# - ya activo con interfaces=all (el defecto: incluye la WAN): NO agrega nada; nos llegaría también la WAN.",
        '# Varias interfaces separadas por coma; nombres con espacios: toda la lista entre comillas, "br clientes,vlan20".',
        "# Si la VLAN de clientes va sobre un bridge, poner el BRIDGE. NUNCA la WAN. Equipos chicos: cache-entries=64k o 32k.",
        "# src-address = IP del router con la que este servidor lo ve (la del inventario). Si ya hay un destino",
        "# hacia este servidor no se agrega otro (duplicaría todas las cifras).",
        "{",
        ":local ok true",
        ":if ([/ip traffic-flow get enabled]) do={",
        "  :local i [:tostr [/ip traffic-flow get interfaces]]",
        '  :put ("traffic-flow ya estaba activo (otro colector) con interfaces=" . $i)',
        '  :if (($i = "all") || ([:len $i] = 0)) do={',
        "    :set ok false",
        '    :put "NO se agrega el destino: con interfaces=all llegaria tambien la WAN. Ver Panel > Exportar NetFlow."',
        "  } else={",
        '    :put "No se cambia interfaces= (es global). Revisar que ninguna de esas sea la WAN o un enlace de transito."',
        "  }",
        "} else={",
        "  /ip traffic-flow set enabled=yes interfaces=" + intf
        + " cache-entries=128k active-flow-timeout=1m inactive-flow-timeout=15s",
        "}",
        f":if ($ok && ([:len [/ip traffic-flow target find dst-address={ip}]] = 0)) do={{",
        f"  /ip traffic-flow target add dst-address={ip} port={puerto} version=9 src-address={origen} "
        "v9-template-refresh=20 v9-template-timeout=1m",
        "}",
        "}",
    ])
    verificar = "\n".join([
        "/ip traffic-flow print",
        "/ip traffic-flow target print detail",
        f"/interface print stats where name={primera}",
        "/ip firewall nat print where chain=srcnat",
        "/ip firewall filter print where action=fasttrack-connection",
        "/interface ethernet switch print",
    ])
    quitar = "\n".join([
        f"/ip traffic-flow target remove [find dst-address={ip}]",
        "# apaga traffic-flow solo si no queda ningún otro colector",
        ":if ([:len [/ip traffic-flow target find]] = 0) do={/ip traffic-flow set enabled=no}",
    ])
    return buscar, activar, verificar, quitar


# ---------- HTML ----------

e = html.escape

CSS = """
:root{--bg:#f6f7f9;--fg:#1d2330;--mut:#5d6677;--card:#fff;--line:#dde1e8;--acc:#1f6feb;--ok:#1a7f37;--warn:#9a6700;--bad:#cf222e}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--fg:#e4e8ef;--mut:#9aa4b5;--card:#171b23;--line:#2a303c;--acc:#4c8dff;--ok:#3fb950;--warn:#d29922;--bad:#f85149}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,-apple-system,Segoe UI,sans-serif}
header{display:flex;gap:16px;align-items:center;padding:12px 20px;border-bottom:1px solid var(--line);background:var(--card);flex-wrap:wrap}
header b{font-size:15px}nav a{color:var(--mut);text-decoration:none;margin-right:14px}nav a.on,nav a:hover{color:var(--acc)}
main{max-width:1200px;margin:0 auto;padding:20px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:16px;margin-bottom:16px;overflow-x:auto}
h1{font-size:20px;margin:0 0 12px}h2{font-size:16px;margin:0 0 10px}.mut{color:var(--mut)}
table{border-collapse:collapse;width:100%;font-variant-numeric:tabular-nums}th,td{padding:6px 8px;border-bottom:1px solid var(--line);text-align:left;white-space:nowrap}
th{color:var(--mut);font-weight:600}td.n,th.n{text-align:right}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:10px;overflow:auto;max-height:70vh;font-size:12px}
button,.btn{background:var(--acc);color:#fff;border:0;border-radius:6px;padding:5px 10px;cursor:pointer;font:inherit;text-decoration:none;display:inline-block}
button.sec{background:transparent;color:var(--acc);border:1px solid var(--acc)}form.inl{display:inline}
.ok{color:var(--ok)}.warn{color:var(--warn)}.bad{color:var(--bad)}
input{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);width:100%;margin:4px 0 10px}
.rejilla{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:0 12px}
label.check{display:flex;gap:8px;align-items:center;margin:4px 0 12px}label.check input{width:auto;margin:0}
.copiable{position:relative}.copiable button{position:absolute;top:6px;right:6px}.copiable pre{padding-right:80px;white-space:pre-wrap;word-break:break-all}
dialog{border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);max-width:520px}dialog::backdrop{background:#0008}
select{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--bg);color:var(--fg);width:100%;margin:4px 0 10px}
form.filtros{display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}form.filtros label{min-width:160px}form.filtros button{margin-bottom:10px}
.cifras{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px 16px}.cifras div{border-left:3px solid var(--line);padding-left:8px}
.cifras b{display:block;font-size:18px}svg.horas{width:100%;height:150px;display:block}svg.horas .baj{fill:var(--acc)}svg.horas .sub{fill:var(--warn)}
.leyenda span{display:inline-block;width:10px;height:10px;margin:0 4px 0 12px;vertical-align:middle}
tr.malo td{color:var(--bad)}tr.ojo td{color:var(--warn)}details{margin-top:8px}summary{cursor:pointer;color:var(--acc)}
"""


JS = """function copiar(id, b) {
  const t = document.getElementById(id).innerText;
  const listo = () => { b.textContent = "Copiado"; setTimeout(() => b.textContent = "Copiar", 1500); };
  if (navigator.clipboard && window.isSecureContext) { navigator.clipboard.writeText(t).then(listo); return; }
  const a = document.createElement("textarea"); a.value = t; document.body.appendChild(a); a.select();
  document.execCommand("copy"); a.remove(); listo();
}"""


def pagina(titulo, cuerpo, activa="", aviso=None, refresco=None):
    nav = "".join(f'<a href="{u}" class="{"on" if u == activa else ""}">{t}</a>' for u, t in
                  [("/", "Panel"), ("/routers", "Routers"), ("/trafico", "Tráfico"), ("/firewall", "Firewall"),
                   ("/muestras", "Muestras"), ("/informes", "Informes"), ("/doc", "Documentación")])
    modal = ""
    if aviso:
        modal = (f'<dialog id="aviso"><p>{e(aviso)}</p><form method="dialog"><button>Cerrar</button></form></dialog>'
                 '<script>document.getElementById("aviso").showModal()</script>')
    meta = f'<meta http-equiv="refresh" content="{refresco}">' if refresco else ""
    return (f'<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" '
            f'content="width=device-width,initial-scale=1">{meta}<title>{e(titulo)} · Perfil de tráfico</title>'
            f'<style>{CSS}</style></head><body><header><b>Perfil de tráfico MikroTik</b><nav>{nav}</nav>'
            f'<form class="inl" method="post" action="/salir" style="margin-left:auto"><button class="sec">Salir</button></form>'
            f'</header><main>{cuerpo}</main>{modal}<script>{JS}</script></body></html>')


def _boton(accion, texto, router="", categoria="", sec=False, confirmar=None):
    js = f' onsubmit="return confirm({e(json.dumps(confirmar))})"' if confirmar else ""
    return (f'<form class="inl" method="post" action="/accion"{js}><input type="hidden" name="accion" value="{accion}">'
            f'<input type="hidden" name="router" value="{e(router)}"><input type="hidden" name="categoria" value="{e(categoria)}">'
            f'<button class="{"sec" if sec else ""}">{texto}</button></form> ')


def vista_panel(aviso=None, nf_router=None, nf_interfaz=None):
    inv = _inventario()
    muestras = _manifiestos()
    filas = []
    for nombre, r in inv.get("routers", {}).items():
        propias = [m for m in muestras if m.get("router") == nombre]
        ultima = propias[0] if propias else {}
        cats = r.get("categorias", {})
        rangos = "<br>".join(f"{e(c)}: {e(', '.join(v))}" for c, v in cats.items())
        acciones = _boton("probar", "Probar conexión", nombre, sec=True) + _boton("descubrir", "Descubrir", nombre, sec=True)
        for c in cats:
            acciones += _boton("contar", f"Contar {e(c)}", nombre, c, sec=True)
            acciones += _boton("recolectar", f"Muestrear {e(c)}", nombre, c,
                               confirmar=f"Tomar una muestra de conntrack de {c} en {nombre} (solo lectura)?")
        filas.append(
            f"<tr><td><b>{e(nombre)}</b><div class='mut'>{e(r.get('host', ''))}:{e(str(r.get('puerto', 22)))}</div>"
            f"{'<span class=ok>muestreo activo</span>' if r.get('activo') else '<span class=warn>muestreo en pausa</span>'}</td>"
            f"<td>{rangos}</td>"
            f"<td class='n'>{len(propias)}</td><td>{e(ultima.get('ts', '—'))}"
            f"{'<div class=warn>' + e(ultima['omitida']) + '</div>' if ultima.get('omitida') else ''}</td>"
            f"<td>{acciones}</td></tr>")
    routers = ("<table><tr><th>Router</th><th>Categorías (CIDR)</th><th class=n>Muestras</th><th>Última</th>"
               "<th>Acciones (solo lectura)</th></tr>" + "".join(filas) + "</table>") if filas else (
        "<p class='mut'>Aún no hay routers. <a class=btn href='/routers'>Agregar router</a></p>")
    categorias = sorted({c for r in inv.get("routers", {}).values() for c in r.get("categorias", {})}) or ["residencial"]
    analizar = "".join(_boton("analizar", f"Analizar {e(c)}", categoria=c) for c in categorias)
    tareas = []
    for nombre in _listar("tareas", "*.log")[:15]:
        p = TAREAS.get(nombre)
        estado = "<span class=warn>en curso</span>" if p and p.poll() is None else (
            "<span class=ok>ok</span>" if "código de salida 0" in _datos("tareas", nombre).read_text(encoding="utf-8", errors="replace")
            else "<span class=bad>revisar</span>")
        tareas.append(f"<tr><td><a href='/tarea?f={quote(nombre)}'>{e(nombre)}</a></td><td>{estado}</td></tr>")
    llave = Path(CFG.get("llave_publica", ""))
    if llave.is_file():
        ip = CFG.get("ip_origen") or "IP_DE_ESTE_SERVIDOR"
        v7, v6, verificar, quitar = comandos_router(llave.read_text().strip(), ip)
        conectar = f"""<p>Pegar en la terminal del MikroTik (Winbox → New Terminal) como administrador. Crea el usuario
<code>trafico</code> del grupo <code>read</code> (no puede cambiar nada) que solo acepta conexiones desde <b>{e(ip)}</b>,
y le carga la llave de este servidor. No lleva clave.</p>
<h3>RouterOS 7</h3>{_copiable("cmd-v7", v7)}
<h3>RouterOS 6</h3>{_copiable("cmd-v6", v6)}
<h3>Comprobar</h3>{_copiable("cmd-ver", verificar)}
<p class=mut>Debe salir el usuario <code>trafico</code> con una llave RSA, y el servicio <code>ssh</code> habilitado. Si ese servicio
tiene <code>address</code> restringido, o el firewall <code>input</code> filtra SSH, hay que permitir {e(ip)}. Si el router ve a este
servidor con otra IP (NAT o VPN de por medio), cambiar <code>address=</code> por esa IP.</p>
<h3>Quitar el acceso</h3>{_copiable("cmd-quitar", quitar)}
<p class=mut>Hecho esto, pasar IP, puerto SSH y rangos de cada categoría para darlo de alta en el inventario.</p>"""
    else:
        conectar = "<p class=bad>No se encontró la llave pública del servidor (reinstalar con deploy/install.sh).</p>"
    ip_col = CFG.get("ip_origen") or "IP_DE_ESTE_SERVIDOR"
    puerto_nf = puerto_netflow()
    routers_inv = inv.get("routers", {})
    nf_router = nf_router if nf_router in routers_inv else ""
    ip_router = None
    if nf_router:
        try:
            ip_router = str(ipaddress.IPv4Address(routers_inv[nf_router].get("exportador") or routers_inv[nf_router].get("host", "")))
        except ValueError:
            ip_router = None  # host por nombre: queda el marcador IP_DEL_ROUTER
    intf = interfaces_ros(nf_interfaz)
    if nf_interfaz and not intf and not aviso:
        aviso = "Nombre de interfaz no válido: no puede llevar comillas, $, [], {}, ;, = ni \\. Se dejó el marcador INTERFAZ-CLIENTES."
    nf_buscar, nf_activar, nf_ver, nf_quitar = comandos_netflow(ip_col, puerto_nf, ip_router, nf_interfaz if intf else None)
    opciones = "<option value=''>(sin elegir: IP_DEL_ROUTER)</option>" + "".join(
        f"<option value='{e(n)}'{' selected' if n == nf_router else ''}>{e(n)}</option>" for n in routers_inv)
    netflow = f"""<p>Hace que el router envíe a <b>{e(ip_col)}</b> (UDP {puerto_nf}) un registro de <b>cada conexión</b> de los clientes:
IP y puerto de origen y destino, protocolo, bytes y paquetes. Es lo mismo en RouterOS 6.49 y 7 (NetFlow v9). Es un cambio en el router:
lo aplica el operador, con respaldo (<code>/system backup save</code>) y en Safe Mode. Este sistema nunca lo aplica solo.</p>
<form method="get" action="/#netflow" class=filtros>
<label>Router (pone su IP en <code>src-address</code>)<select name="nf_router">{opciones}</select></label>
<label>Interfaz de clientes (opcional)<input name="nf_interfaz" placeholder="bridge-clientes" value="{e(nf_interfaz or '')}"></label>
<button class=sec>Generar comandos</button></form>
<h3>0. Mirar antes y encontrar la interfaz de clientes</h3>{_copiable("nf-buscar", nf_buscar)}
<p class=mut>Si <code>/ip traffic-flow print</code> ya dice <code>enabled: yes</code>, el router exporta a <b>otro colector</b>:
<code>interfaces=</code> es global y cambiarlo cambiaría lo que recibe ese otro sistema. El paso 1 lo comprueba solo: si el otro
colector usa interfaces concretas, no las toca, las muestra (revisar que ninguna sea la WAN) y solo agrega el destino. Si usa
<code>interfaces=all</code> (el valor por defecto), <b>no agrega nada</b>: nos llegaría también la WAN, que multiplica el volumen y ya
tumbó un servidor. En ese caso hay que acordar con el dueño del otro colector cambiar <code>interfaces=</code> a la de clientes
(también le conviene) o no exportar a este servidor desde ese router. La interfaz de clientes es la que tiene la IP gateway de los clientes (por ejemplo <code>100.64.0.1/22</code>);
si los clientes van por VLAN montada sobre un bridge, poner el <b>bridge</b>. Si entran por <b>PPPoE</b>, avisar antes de aplicar:
ese caso necesita otra configuración.</p>
<h3>1. Activar NetFlow</h3>{_copiable("nf-activar", nf_activar)}
<p class=mut>Reemplazar <code>INTERFAZ-CLIENTES</code> (o escribirla arriba) y, si no se eligió router, <code>IP_DEL_ROUTER</code> antes de pegar.
Nombres con espacios: toda la lista entre comillas. <code>cache-entries=128k</code> evita que un core llene la tabla (4k por defecto);
en equipos chicos, 64k o 32k. <code>src-address</code> es la IP con la que este servidor reconoce al router: si el envío sale por NAT o VPN
con otra IP, anotarla en Routers → «IP desde la que exporta NetFlow», o aparecerá como <b>exportador desconocido</b> en Tráfico → Salud.
Con poco tráfico la plantilla v9 puede tardar <b>varios minutos</b> en llegar (<code>v9-template-timeout=1m</code> la reenvía cada minuto):
mientras tanto llegan archivos con 0 flujos. El tráfico acelerado por hardware (hw-offload) no se exporta.</p>
<h3>2. Comprobar</h3>{_copiable("nf-ver", nf_ver)}
<p class=mut>Debe salir <code>enabled: yes</code>, la interfaz correcta y un target hacia {e(ip_col)}:{puerto_nf} versión 9. Ninguna regla
srcnat debe cambiar el origen del envío hacia {e(ip_col)} (si la hay, el operador decide una excepción
<code>chain=srcnat dst-address={e(ip_col)} action=accept</code> arriba de todo). FastTrack con <code>hw-offload=yes</code> o
<code>l3-hw-offloading: yes</code> en el switch (v7) = ese tráfico no se exporta. En <a href="/trafico">Tráfico → Salud</a> el router
debe aparecer con archivos del último minuto.</p>
<h3>Quitar</h3>{_copiable("nf-quitar", nf_quitar)}
<p class=mut>Quita solo el destino hacia este servidor; apaga Traffic Flow únicamente si no queda ningún otro colector.</p>"""
    return pagina("Panel", f"""
<h1>Panel</h1>
<div class=card><h2>Routers</h2>{routers}</div>
<div class=card><h2>Análisis</h2><p class=mut>Genera el perfil con las muestras de los últimos 7 días. También corre solo cada noche a las 23:30.</p>{analizar}</div>
<div class=card><h2>Tareas recientes</h2>{'<table>' + ''.join(tareas) + '</table>' if tareas else '<p class=mut>Sin tareas todavía.</p>'}</div>
<div class=card><h2>Programación (systemd)</h2><pre>{e(_timers())}</pre></div>
<div class=card><h2>Conectar un router</h2>{conectar}</div>
<div class=card id="netflow"><h2>Exportar NetFlow</h2>{netflow}</div>
""", "/", aviso=aviso)


def _copiable(ident, texto):
    return (f'<div class=copiable><button class=sec data-id="{ident}" onclick="copiar(this.dataset.id, this)">Copiar</button>'
            f'<pre id="{ident}">{e(texto)}</pre></div>')


def _post_router(ruta, nombre, texto, extra="", sec=True, confirmar=None):
    js = f' onsubmit="return confirm({e(json.dumps(confirmar))})"' if confirmar else ""
    return (f'<form class="inl" method="post" action="{ruta}"{js}><input type="hidden" name="nombre" value="{e(nombre)}">'
            f'{extra}<button class="{"sec" if sec else ""}">{texto}</button></form> ')


def vista_routers(editar=None, aviso=None):
    inv = _inventario()
    filas = []
    for nombre, r in inv["routers"].items():
        cats = "<br>".join(f"{e(c)}: {e(', '.join(v))}" for c, v in r.get("categorias", {}).items())
        activo = r.get("activo", False)
        conmutar = _post_router("/routers/activo", nombre, "Pausar muestreo" if activo else "Activar muestreo",
                                "" if activo else '<input type="hidden" name="activo" value="on">', sec=activo)
        filas.append(
            f"<tr><td><b>{e(nombre)}</b></td><td>{e(r.get('host', ''))}:{r.get('puerto', 22)}</td>"
            f"<td>{e(r.get('usuario', ''))}</td><td>{cats}</td><td>{e(r.get('exportador', '—'))}</td>"
            f"<td>{'<span class=ok>activo</span>' if activo else '<span class=warn>en pausa</span>'}</td>"
            f"<td><a class='btn' href='/routers?editar={quote(nombre)}'>Editar</a> {conmutar}"
            + _post_router("/routers/borrar", nombre, "Eliminar",
                           confirmar=f"¿Eliminar {nombre} del inventario? Las muestras guardadas no se borran.") + "</td></tr>")
    tabla = ("<table><tr><th>Nombre</th><th>IP:puerto SSH</th><th>Usuario</th><th>Rangos</th><th>Exporta NetFlow desde</th>"
             "<th>Muestreo</th><th></th></tr>" + "".join(filas) + "</table>") if filas else "<p class=mut>Todavía no hay routers.</p>"

    r = inv["routers"].get(editar or "", {})
    cats = r.get("categorias", {})
    valor = lambda k, defecto="": e(str(r.get(k, defecto)))  # noqa: E731
    titulo = f"Editar «{e(editar)}»" if r else "Agregar router"
    formulario = f"""<form method="post" action="/routers/guardar" class=formulario>
<input type="hidden" name="anterior" value="{e(editar) if r else ''}">
<div class=rejilla>
<label>Nombre (sin espacios)<input name="nombre" required pattern="[a-z0-9][a-z0-9-]{{0,39}}" placeholder="core-centro" value="{e(editar) if r else ''}"></label>
<label>IP del router (SSH)<input name="host" required placeholder="192.0.2.1" value="{valor('host')}"></label>
<label>Puerto SSH<input name="puerto" type="number" min="1" max="65535" value="{valor('puerto', 22)}"></label>
<label>Usuario<input name="usuario" value="{valor('usuario', 'trafico')}"></label>
</div>
<label>Rangos residenciales (separados por coma o espacio)<input name="residencial" placeholder="100.64.0.0/22, 100.64.8.0/23"
 value="{e(', '.join(cats.get('residencial', [])))}"></label>
<label>Rangos empresariales (opcional)<input name="empresarial" placeholder="198.51.100.0/26" value="{e(', '.join(cats.get('empresarial', [])))}"></label>
<label>IP desde la que exporta NetFlow (opcional; solo si no es la misma IP del router)<input name="exportador"
 placeholder="vacío = la misma IP" value="{valor('exportador')}"></label>
<label class=check><input type="checkbox" name="activo" {'checked' if r.get('activo') else ''}> Muestreo automático en las franjas del día</label>
<button>{'Guardar cambios' if r else 'Agregar router'}</button> {'<a href="/routers">Cancelar</a>' if r else ''}
</form>"""
    return pagina("Routers", f"""<h1>Routers</h1>
<div class=card><h2>Inventario</h2>{tabla}</div>
<div class=card><h2>{titulo}</h2>
<p class=mut>Antes, en el router, pegar los comandos de <a href="/">Panel → Conectar un router</a>. Después de agregarlo:
Panel → <b>Probar conexión</b>.</p>{formulario}</div>""", "/routers", aviso=aviso)


def vista_muestras():
    filas = "".join(
        f"<tr><td>{e(m.get('ts', ''))}</td><td>{e(m.get('router', ''))}</td><td>{e(m.get('categoria', ''))}</td>"
        f"<td>{e(m.get('cidr', ''))}</td><td class=n>{m.get('conexiones_router', '')}</td>"
        f"<td>{'<span class=warn>' + e(m['omitida']) + '</span>' if m.get('omitida') else '<span class=ok>guardada</span>'}</td></tr>"
        for m in _manifiestos()[:300])
    desc = "".join(f"<li><a href='/descubrimiento?f={quote(n)}'>{e(n)}</a></li>" for n in _listar("descubrimiento", "*.txt")[:30])
    return pagina("Muestras", f"""<h1>Muestras</h1>
<div class=card><table><tr><th>Fecha</th><th>Router</th><th>Categoría</th><th>CIDR</th><th class=n>Conexiones</th><th>Estado</th></tr>
{filas or '<tr><td colspan=6 class=mut>Sin muestras todavía.</td></tr>'}</table></div>
<div class=card><h2>Descubrimientos</h2><ul>{desc or '<li class=mut>Ninguno.</li>'}</ul></div>""", "/muestras")


def vista_informes():
    items = "".join(f"<li><a href='/informe?f={quote(n)}'>{e(n)}</a></li>" for n in _listar("informes", "*.json"))
    lecturas = "".join(f"<li><a href='/lectura?f={quote(n)}'>{e(n)}</a></li>" for n in _listar("informes", "*-lectura.md"))
    return pagina("Informes", f"""<h1>Informes</h1>
<div class=card><h2>Perfiles generados</h2><ul>{items or '<li class=mut>Ninguno: usar «Analizar» en el panel.</li>'}</ul></div>
<div class=card><h2>Lecturas del agente</h2><ul>{lecturas or '<li class=mut>Ninguna.</li>'}</ul></div>""", "/informes")


def _bytes(n):
    for u in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.0f} {u}"
        n /= 1024
    return f"{n:.0f} PiB"


def _tabla_servicios(filas, con_bytes=True):
    cab = "<tr><th>Proto/puerto</th><th>Servicio</th><th class=n>% abonados</th><th class=n>Abonados</th><th class=n>Conexiones</th>"
    cab += "<th class=n>Bytes</th></tr>" if con_bytes else "</tr>"
    cuerpo = "".join(
        f"<tr><td>{e(f['proto'])}/{f['puerto'] if f['puerto'] is not None else '-'}</td><td>{e(f['servicio'])}</td>"
        f"<td class=n>{f['pct_abonados']}</td><td class=n>{f['abonados']}</td><td class=n>{f['conexiones']}</td>"
        + (f"<td class=n>{_bytes(f['bytes'])}</td>" if con_bytes else "") + "</tr>" for f in filas)
    return f"<table>{cab}{cuerpo or '<tr><td colspan=6 class=mut>Nada.</td></tr>'}</table>"


def vista_informe(ruta):
    p = json.loads(ruta.read_text(encoding="utf-8"))
    r = p["resumen"]
    etiquetas = {"conexiones": "Conexiones salientes", "udp": "Conexiones UDP", "puertos": "Puertos destino distintos",
                 "ips": "IP destino distintas", "syn": "TCP sin respuesta (syn-sent)",
                 "peers_udp": "Pares UDP distintos (P2P)"}
    dns = "".join(f"<tr><td>{e(f['proto'])}/{f['puerto']}</td><td>{e(f['servidor'])}</td><td>{e(f['red'])}</td>"
                  f"<td class=n>{f['pct_abonados']}</td><td class=n>{f['conexiones']}</td></tr>" for f in p.get("dns", []))
    no_pub = "".join(f"<tr><td>{e(f['red'])}</td><td class=n>{f['abonados']}</td><td class=n>{f['conexiones']}</td></tr>"
                     for f in p.get("destinos_no_publicos", []))
    p2p = "".join(f"<li>{e(f['abonado'])} en {e(f['router'])} ({e(f['muestra'])}): {f['peers_udp']} pares UDP</li>"
                  for f in p.get("p2p", []))
    percent = "".join(
        f"<tr><td>{t}</td>" + "".join(f"<td class=n>{p['por_abonado'].get(k, {}).get(c, '-')}</td>"
                                      for c in ("p50", "p90", "p99", "p99.9", "max")) + "</tr>"
        for k, t in etiquetas.items())
    destinos = "".join(f"<tr><td>{e(d['destino'])}</td><td class=n>{d['pct_abonados']}</td><td class=n>{d['conexiones']}</td>"
                       f"<td class=n>{_bytes(d['bytes'])}</td></tr>" for d in p["destinos"])
    senales = "".join(
        f"<li><b>{e(n)}</b>: {len(f)} abonados — " + ", ".join(
            f"{e(x['abonado'])} ({x['conexiones']} conex., {x['destinos_distintos']} destinos)" for x in f[:8]) + "</li>"
        for n, f in p["senales"].items())
    senales += "".join(f"<li class=bad>Barrido: {e(b['abonado'])} en {e(b['router'])} ({e(b['muestra'])}) → {e(b['puerto'])} "
                       f"{e(b['servicio'])} hacia {b['destinos_distintos']} destinos</li>" for b in p["barridos"][:20])
    routers = "".join(f"<tr><td>{e(n)}</td><td class=n>{v['muestras']}</td><td class=n>{v['abonados']}</td>"
                      f"<td class=n>{v['conexiones']}</td></tr>" for n, v in p["por_router"].items())
    return pagina("Informe", f"""<h1>Perfil — {e(p['categoria'])}</h1>
<div class=card><p>Generado {e(p['generado'])} · Routers: {e(', '.join(r['routers']))} · Muestras: {r['muestras']} ·
Horas: {e(', '.join(r['horas_muestreadas']))} · Abonados: {r['abonados_observados']} · Conexiones: {r['conexiones_analizadas']} ·
Destinos por {e(r['destinos_agrupados_por'])}</p>
<p class=mut>Los bytes son orientativos (FastTrack por hardware congela los contadores). Ordenado por % de abonados.</p></div>
<div class=card><h2>Servicios salientes</h2>{_tabla_servicios(p['salientes'])}</div>
<div class=card><h2>Entrantes hacia abonados</h2>{_tabla_servicios(p['entrantes'], False)}</div>
<div class=card><h2>Por abonado y muestra (base para límites)</h2><table><tr><th>Métrica</th><th class=n>p50</th><th class=n>p90</th>
<th class=n>p99</th><th class=n>p99.9</th><th class=n>máx</th></tr>{percent}</table></div>
<div class=card><h2>Señales a revisar</h2><ul>{senales or '<li class=mut>Sin señales.</li>'}</ul></div>
<div class=card><h2>Destinos</h2><table><tr><th>Destino</th><th class=n>% abonados</th><th class=n>Conexiones</th><th class=n>Bytes</th></tr>{destinos}</table></div>
<div class=card><h2>DNS: a qué resolvers preguntan</h2><p class=mut>Si mucha gente usa resolvers externos o DNS cifrado (853), el DNS forzado por dst-nat no los alcanza.</p>
<table><tr><th>Proto/puerto</th><th>Servidor</th><th>Red</th><th class=n>% abonados</th><th class=n>Conexiones</th></tr>{dns or '<tr><td colspan=5 class=mut>Nada.</td></tr>'}</table></div>
<div class=card><h2>Destinos no públicos</h2><p class=mut>Redes privadas o reservadas fuera de la categoría: servicios internos del ISP, rutas mal puestas o fugas.</p>
<table><tr><th>Red /24</th><th class=n>Abonados</th><th class=n>Conexiones</th></tr>{no_pub or '<tr><td colspan=3 class=mut>Nada.</td></tr>'}</table></div>
<div class=card><h2>Posible P2P</h2><ul>{p2p or '<li class=mut>Ninguno.</li>'}</ul></div>
<div class=card><h2>Por router</h2><table><tr><th>Router</th><th class=n>Muestras</th><th class=n>Abonados</th><th class=n>Conexiones</th></tr>{routers}</table></div>
""", "/informes")


# ---------- NetFlow: Tráfico y Firewall ----------

SIN_NETFLOW = """<div class=card><h2>Todavía no hay datos NetFlow</h2>
<p>El colector aún no recibió ni procesó flujos de ningún router. Configurar el envío con los comandos de
<a href="/#netflow">Panel → Exportar NetFlow</a> y esperar un par de minutos: cada archivo es un minuto y se procesa al cerrarse;
con poco tráfico la plantilla v9 puede tardar varios minutos más.</p></div>"""

_PERCENTILES = (("flujos", "Flujos distintos (5-tuplas)"), ("tcp_nuevas", "Conexiones TCP nuevas (SYN)"),
                ("udp", "Flujos UDP distintos"), ("ips", "IP remotas distintas"), ("puertos", "Puertos remotos distintos"),
                ("peers_udp", "Pares UDP (P2P)"), ("syn", "TCP sin respuesta (SYN sin ACK)"))
_ORDEN_DESTINOS = ("bytes", "abonados")
_ORDEN_CONSUMO = ("bajada", "subida", "total", "flujos")
_CATEGORIA = re.compile(r"[\w-]{1,40}", re.ASCII)


def _t(v):
    """Texto de la base, escapado; '—' si falta."""
    return "—" if v is None or v == "" else e(str(v))


def _num(v):
    if isinstance(v, bool) or not isinstance(v, (int, float)):
        return _t(v)
    texto = f"{v:,.1f}" if isinstance(v, float) else f"{v:,}"
    return texto.replace(",", " ")


def _b(v):
    return _bytes(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else "—"


def _tabla(columnas, filas, vacio="Sin datos en el periodo."):
    """columnas = [(título, numérica)]; filas = listas de celdas YA escapadas (usar _t, _num, _b)."""
    cab = "".join(("<th class=n>" if n else "<th>") + t + "</th>" for t, n in columnas)
    cuerpo = []
    for f in filas:
        clase = ""
        if isinstance(f, tuple):  # (clase de fila, celdas)
            clase, f = f
        celdas = "".join(("<td class=n>" if n else "<td>") + c + "</td>" for c, (_, n) in zip(f, columnas))
        cuerpo.append(f"<tr class='{clase}'>{celdas}</tr>" if clase else f"<tr>{celdas}</tr>")
    if not cuerpo:
        cuerpo = [f"<tr><td colspan={len(columnas)} class=mut>{vacio}</td></tr>"]
    return f"<table><tr>{cab}</tr>{''.join(cuerpo)}</table>"


def _selector(nombre, opciones, actual, todos=None):
    ops = [f"<option value=''>{e(todos)}</option>"] if todos is not None else []
    ops += [f"<option value='{e(o)}'{' selected' if o == actual else ''}>{e(o)}</option>" for o in opciones]
    return f"<select name='{nombre}'>{''.join(ops)}</select>"


def _filtros(q, routers, categorias, periodos=None, defecto="hoy"):
    """Valida router (vacío o conocido), categoría (^[\\w-]+$) y periodo. Lo inválido vuelve al valor por defecto
    y deja un aviso para el modal; el valor recibido nunca se pinta sin escapar."""
    avisos = []
    router = q.get("router") or ""
    if router and router not in routers:
        avisos.append(f"Router «{router[:60]}» desconocido: se muestran todos los routers.")
        router = ""
    categoria = q.get("categoria") or ""
    if categoria and not _CATEGORIA.fullmatch(categoria):
        avisos.append(f"Categoría «{categoria[:60]}» no válida.")
        categoria = ""
    if not categoria:
        categoria = "residencial" if "residencial" in categorias or not categorias else categorias[0]
    periodo = q.get("periodo") or defecto
    if periodos is not None and periodo not in periodos:
        avisos.append(f"Periodo «{periodo[:60]}» desconocido (válidos: {', '.join(periodos)}): se usa «{defecto}».")
        periodo = defecto
    return router, categoria, periodo, avisos


def _grafico_horas(serie):
    """Barras apiladas bajada/subida en SVG en línea (sin librerías). Cada barra trae su detalle en <title>."""
    if not serie:
        return "<p class=mut>Sin datos en el periodo.</p>"
    valores = [((s.get("bytes_bajada") or 0), (s.get("bytes_subida") or 0)) for s in serie]
    maximo = max(b + s for b, s in valores) or 1
    ancho, alto = 10, 100
    barras = []
    for i, (s, (baj, sub)) in enumerate(zip(serie, valores)):
        hb, hs = baj * alto / maximo, sub * alto / maximo
        detalle = (f"{_t(s.get('inicio'))}: bajada {_b(baj)}, subida {_b(sub)}, {_num(s.get('flujos'))} flujos, "
                   f"{_num(s.get('abonados_max_ventana'))} abonados (máx. por minuto)")
        barras.append(f"<g><title>{detalle}</title><rect class=baj x='{i * ancho}' y='{alto - hb - hs:.2f}' width='{ancho - 2}' "
                      f"height='{hb:.2f}'/><rect class=sub x='{i * ancho}' y='{alto - hs:.2f}' width='{ancho - 2}' height='{hs:.2f}'/></g>")
    svg = (f"<svg class=horas viewBox='0 0 {len(serie) * ancho} {alto}' preserveAspectRatio='none' role='img' "
           f"aria-label='Bytes por intervalo'>{''.join(barras)}</svg>")
    leyenda = (f"<div class='leyenda mut'>{_t(serie[0].get('inicio'))} → {_t(serie[-1].get('inicio'))} · máximo {_b(maximo)}"
               "<span style='background:var(--acc)'></span>bajada<span style='background:var(--warn)'></span>subida</div>")
    tabla = _tabla([("Inicio", False), ("Bajada", True), ("Subida", True), ("Flujos", True), ("Abonados máx./min", True)],
                   [[_t(s.get("inicio")), _b(s.get("bytes_bajada")), _b(s.get("bytes_subida")), _num(s.get("flujos")),
                     _num(s.get("abonados_max_ventana"))] for s in serie])
    return f"{svg}{leyenda}<details><summary>Ver tabla</summary>{tabla}</details>"


def _cifra(titulo, valor, clase=""):
    return f"<div><span class=mut>{titulo}</span><b class='{clase}'>{valor}</b></div>"


def _tabla_puertos(filas):
    return _tabla([("Puerto", False), ("Servicio", False), ("% abonados", True), ("Abonados", True), ("Flujos", True),
                   ("Subida", True), ("Bajada", True)],
                  [[_t(f.get("etiqueta")), _t(f.get("servicio")), _num(f.get("pct_abonados")), _num(f.get("abonados")),
                    _num(f.get("flujos")), _b(f.get("bytes_subida")), _b(f.get("bytes_bajada"))] for f in filas])


def _tabla_senal(grupos):
    """{nombre: [filas]} de senales()['sensibles'|'reflectores']."""
    filas = [[_t(nombre), _t(x.get("router")), _t(x.get("abonado")), _num(x.get("flujos")), _num(x.get("remotos_max_ventana")),
              _num(x.get("ventanas")), _t(x.get("ultima"))]
             for nombre, lista in (grupos or {}).items() for x in lista]
    return _tabla([("Señal", False), ("Router", False), ("Abonado", False), ("Flujos", True), ("Remotos máx./min", True),
                   ("Minutos", True), ("Última", False)], filas, "Ninguna.")


def _salud(s):
    exp = s.get("exportadores") or []
    filas, desconocidos, fuera, perdidas = [], [], [], []
    for x in exp:
        pct = x.get("pct_fuera_categoria") or 0
        clase = ""
        if x.get("router") is None:
            clase = "malo"
            desconocidos.append(x.get("exportador"))
        elif pct > 30:
            clase = "ojo"
            fuera.append(x.get("router"))
        if (x.get("secuencia_perdida") or 0) > 0:
            clase = clase or "ojo"
            perdidas.append(x.get("router") or x.get("exportador"))
        filas.append((clase, [_t(x.get("exportador")), _t(x.get("router")) if x.get("router") is not None else "desconocido",
                              _t(x.get("ultimo_archivo")), _num(x.get("archivos")), _num(x.get("flujos")),
                              _num(x.get("flujos_categoria")), _num(pct), _num(x.get("secuencia_perdida")),
                              _b(x.get("bytes_subida")), _b(x.get("bytes_bajada")), _num(x.get("errores"))]))
    tabla = _tabla([("Exportador", False), ("Router", False), ("Último archivo", False), ("Archivos", True), ("Flujos", True),
                    ("De categoría", True), ("% fuera", True), ("Secuencia perdida", True), ("Subida", True), ("Bajada", True),
                    ("Errores", True)], filas, "Ningún exportador en las últimas 24 h.")
    notas = []
    if desconocidos:
        notas.append(f"<p class=bad>Exportador desconocido ({e(', '.join(str(d) for d in desconocidos))}): llegan flujos desde una IP "
                     "que no es la de ningún router del inventario y no se procesan. Anotar esta IP en Routers → «IP desde la que "
                     "exporta NetFlow» del router que corresponda.</p>")
    if fuera:
        notas.append(f"<p class=warn>Más del 30 % de los flujos de {e(', '.join(str(r) for r in fuera))} no son de ninguna categoría: "
                     "¿la WAN está en <code>interfaces=</code>? ¿faltan rangos en el inventario?</p>")
    if perdidas:
        notas.append(f"<p class=warn>Se pierden paquetes de exportación en {e(', '.join(str(r) for r in perdidas))} "
                     "(secuencia perdida): faltan flujos en esos minutos.</p>")
    d = s.get("disco") or {}
    estado = d.get("estado") or "—"
    cifras = "".join([
        _cifra("Archivos pendientes", _num(s.get("pendientes"))),
        _cifra("En error", _num(s.get("en_error")), "bad" if s.get("en_error") else ""),
        _cifra("Descartados (disco)", _num(s.get("descartados")), "bad" if s.get("descartados") else ""),
        _cifra("Última ejecución", _t(s.get("ultima_ejecucion"))),
        _cifra("Disco libre", f"{_b(d.get('libre_bytes'))} ({_num(d.get('libre_pct'))} %)",
               {"ok": "ok", "aviso": "warn", "critico": "bad"}.get(estado, "")),
        _cifra("Crudo nfcapd", _b(d.get("crudo_bytes"))), _cifra("Base", _b(d.get("db_bytes"))),
        _cifra("Estado del disco", _t(estado), {"ok": "ok", "aviso": "warn", "critico": "bad"}.get(estado, "")),
    ])
    return f"<div class=cifras>{cifras}</div>{tabla}{''.join(notas)}"


def vista_trafico(q):
    """Página Tráfico: lo que dicen los flujos NetFlow de una categoría, por router y periodo."""
    F, con = _abrir_flujos()
    if con is None:
        return pagina("Tráfico", "<h1>Tráfico (NetFlow)</h1>" + SIN_NETFLOW, "/trafico")
    inv = _inventario()
    try:
        routers = sorted(set(inv.get("routers", {})) | set(F.routers_con_datos(con)))
        categorias = sorted(set(F.categorias_con_datos(con))
                            | {c for r in inv.get("routers", {}).values() for c in r.get("categorias", {})})
        periodos = tuple(getattr(F, "PERIODOS", ("hoy", "ayer", "7d", "30d")))
        router, categoria, periodo, avisos = _filtros(q, routers, categorias, periodos, "hoy")
        orden_d = q.get("orden_destinos") if q.get("orden_destinos") in _ORDEN_DESTINOS else "bytes"
        orden_c = q.get("orden_consumo") if q.get("orden_consumo") in _ORDEN_CONSUMO else "bajada"
        rt = router or None
        r = F.resumen(con, categoria, rt, periodo)
        serie = F.por_hora(con, categoria, rt, periodo)
        destinos = F.top_destinos(con, categoria, rt, periodo, orden=orden_d, limite=50)
        salientes = F.top_puertos(con, categoria, rt, periodo, sentido="saliente", orden="abonados", limite=80)
        entrantes = F.top_puertos(con, categoria, rt, periodo, sentido="entrante", orden="abonados", limite=80)
        exactos = F.top_puertos_exactos(con, categoria, rt, periodo, limite=100)
        consumo = F.top_consumidores(con, categoria, rt, periodo, orden=orden_c, limite=50)
        perc = F.percentiles_abonado(con, categoria, rt, periodo)
        sen = F.senales(con, categoria, rt, periodo, limite=20)
        salud = F.salud(con, Path(CFG["datos"]), 24)
        ventanas = F.ventanas_router(con, router, 60) if router else []
        interfaces = F.interfaces_router(con, router, periodo) if router else []
    except (sqlite3.Error, ValueError, OSError) as err:
        return pagina("Tráfico", f"<h1>Tráfico (NetFlow)</h1><div class=card><p class=bad>No se pudo leer la base NetFlow: "
                      f"{e(str(err))}</p></div>", "/trafico")
    finally:
        con.close()

    filtros = (f"<form method=get action='/trafico' class=filtros>"
               f"<label>Router{_selector('router', routers, router, 'Todos')}</label>"
               f"<label>Categoría{_selector('categoria', categorias or [categoria], categoria)}</label>"
               f"<label>Periodo{_selector('periodo', periodos, periodo)}</label>"
               f"<label>Destinos por{_selector('orden_destinos', _ORDEN_DESTINOS, orden_d)}</label>"
               f"<label>Consumo por{_selector('orden_consumo', _ORDEN_CONSUMO, orden_c)}</label>"
               f"<button>Ver</button></form>"
               f"<p class=mut><a href='/firewall?{e(urlencode({'router': router, 'categoria': categoria}))}'>"
               "Firewall de esta categoría →</a></p>")

    desconocidos = [x for x in salud.get("exportadores") or [] if x.get("router") is None]
    relacion = r.get("relacion_bajada_subida")
    modo = " (máximo diario)" if r.get("abonados_modo") == "max_diario" else ""
    resumen = "".join([
        _cifra("Abonados activos" + modo, _num(r.get("abonados_activos"))),
        _cifra("Flujos", _num(r.get("flujos"))),
        _cifra("Subida", _b(r.get("bytes_subida"))), _cifra("Bajada", _b(r.get("bytes_bajada"))),
        _cifra("Bajada / subida", _num(relacion), "warn" if relacion is None or relacion < 0.5 else ""),
        _cifra("Días con datos", _num(r.get("dias_con_datos"))),
        _cifra("Última ventana", _t(r.get("ultima_ventana"))),
        _cifra("Archivos pendientes", _num(r.get("pendientes"))),
        _cifra("Exportadores desconocidos", _num(len(desconocidos)), "bad" if desconocidos else ""),
    ])
    notas = []
    if relacion is None or relacion < 0.5:
        notas.append("<p class=warn>No llega la bajada: Traffic Flow solo exporta lo que entra por las interfaces listadas "
                     "(ver <a href='/doc#netflow-sentido'>Documentación → subida y bajada</a>). Las conexiones se ven todas; "
                     "los bytes de bajada no.</p>")
    if modo:
        notas.append("<p class=mut>En 30 días los abonados distintos son el máximo diario, no un conteo exacto.</p>")
    if desconocidos:
        notas.append("<p class=bad>Hay exportadores desconocidos: ver Salud.</p>")
    sin_datos = "" if r.get("ultima_ventana") else SIN_NETFLOW

    dest = _tabla([("ASN", True), ("Nombre", False), ("País", False), ("Abonados", True), ("% abonados", True),
                   ("Flujos", True), ("Subida", True), ("Bajada", True), ("Total", True)],
                  [[_t(d.get("asn")), _t(d.get("nombre")), _t(d.get("pais")), _num(d.get("abonados")),
                    _num(d.get("pct_abonados")), _num(d.get("flujos")), _b(d.get("bytes_subida")), _b(d.get("bytes_bajada")),
                    _b(d.get("bytes"))] for d in destinos])
    sin_cat = _tabla([("Sentido", False), ("Proto", False), ("Puerto", True), ("Servicio", False), ("Flujos", True),
                      ("Bytes", True), ("Abonados máx./min", True)],
                     [[_t(x.get("sentido")), _t(x.get("proto")), _t(x.get("puerto")), _t(x.get("servicio")),
                       _num(x.get("flujos")), _b(x.get("bytes")), _num(x.get("abonados_max_ventana"))] for x in exactos])
    cons = _tabla([("Router", False), ("Abonado", False), ("Bajada", True), ("Subida", True), ("Flujos", True),
                   ("Días activo", True), ("Máx. flujos/min", True), ("Máx. IP/min", True), ("Máx. pares UDP/min", True)],
                  [[_t(x.get("router")), _t(x.get("abonado")), _b(x.get("bytes_bajada")), _b(x.get("bytes_subida")),
                    _num(x.get("flujos")), _num(x.get("dias_activo")), _num(x.get("max_flujos")), _num(x.get("max_ips")),
                    _num(x.get("max_peers_udp"))] for x in consumo])
    pct = _tabla([("Métrica (por abonado y MINUTO)", False)] + [(c, True) for c in ("p50", "p90", "p99", "p99.9", "máx", "n")],
                 [[t] + [_num(perc[k].get(c)) for c in ("p50", "p90", "p99", "p99.9", "max", "n")]
                  for k, t in _PERCENTILES if k in perc], "Sin observaciones en el periodo.")
    barridos = _tabla([("Router", False), ("Abonado", False), ("Puerto", False), ("Servicio", False),
                       ("Remotos máx./min", True), ("Minutos", True), ("Última", False)],
                      [[_t(x.get("router")), _t(x.get("abonado")), _t(x.get("puerto")), _t(x.get("servicio")),
                        _num(x.get("remotos_max_ventana")), _num(x.get("ventanas")), _t(x.get("ultima"))]
                       for x in sen.get("barridos") or []], "Ninguno.")
    p2p = _tabla([("Router", False), ("Abonado", False), ("Pares UDP máx./min", True), ("Minutos", True), ("Última", False)],
                 [[_t(x.get("router")), _t(x.get("abonado")), _num(x.get("peers_udp_max")), _num(x.get("ventanas")),
                   _t(x.get("ultima"))] for x in sen.get("p2p") or []], "Ninguno.")
    dns = _tabla([("Proto/puerto", False), ("Servidor", False), ("Red", False), ("Abonados", True), ("% abonados", True),
                  ("Flujos", True)],
                 [[_t(x.get("proto")) + "/" + _t(x.get("puerto")), _t(x.get("servidor")), _t(x.get("red")),
                   _num(x.get("abonados")), _num(x.get("pct_abonados")), _num(x.get("flujos"))] for x in sen.get("dns") or []],
                 "Nada.")
    no_pub = _tabla([("Red /24", False), ("Abonados", True), ("Flujos", True), ("Bytes", True)],
                    [[_t(x.get("red")), _num(x.get("abonados")), _num(x.get("flujos")), _b(x.get("bytes"))]
                     for x in sen.get("destinos_no_publicos") or []], "Nada.")
    if router:
        vent = _tabla([("Minuto", False), ("Flujos total", True), ("De categoría", True), ("Subida", True), ("Bajada", True),
                       ("Secuencia perdida", True), ("Estado", False)],
                      [("malo" if x.get("estado") not in ("ok", "vacio") else "",
                        [_t(x.get("ventana")), _num(x.get("flujos_total")), _num(x.get("flujos_categoria")),
                         _b(x.get("bytes_subida")), _b(x.get("bytes_bajada")), _num(x.get("secuencia_perdida")),
                         _t(x.get("estado"))]) for x in ventanas], "Sin archivos en la última hora.")
        vent = f"""<h3>Minuto a minuto (última hora) de {e(router)}</h3>
<p class=mut>Para medir la cobertura: anotar en el router <code>/interface print stats</code> de la interfaz de clientes al inicio y al final
de unos minutos y comparar <code>rx-byte</code> (lo que suben los abonados) con la suma de <b>Subida</b> de esos minutos, y <code>tx-byte</code>
con <b>Bajada</b>. Subida ≈ rx y bajada ≈ 0: Traffic Flow solo exporta lo que entra por la interfaz. Las dos muy por debajo: FastTrack o
hw-offload no se están exportando.</p>{vent}"""
        intf = _tabla([("ifIndex entrada", True), ("ifIndex salida", True), ("Flujos", True), ("Bytes", True)],
                      [[_t(x.get("entrada")), _t(x.get("salida")), _num(x.get("flujos")), _b(x.get("bytes"))]
                       for x in interfaces])
        intf = ("<p class=mut>ifIndex (número SNMP de la interfaz en el router) por donde entra y sale el tráfico de abonados. "
                "Si aparece una interfaz que no es la de clientes, revisar <code>interfaces=</code> de Traffic Flow.</p>" + intf)
    else:
        vent = "<p class=mut>Elegir un router para ver su minuto a minuto de la última hora.</p>"
        intf = "<p class=mut>Elegir un router para ver sus interfaces.</p>"

    periodo_txt = f"{e(categoria)} · {e(', '.join(str(x) for x in r.get('routers') or []) or 'todos los routers')} · " \
                  f"{_t(r.get('desde'))} a {_t(r.get('hasta'))} ({e(periodo)})"
    cuerpo = f"""<h1>Tráfico (NetFlow)</h1>
<div class=card>{filtros}</div>{sin_datos}
<div class=card><h2>Resumen</h2><p class=mut>{periodo_txt}</p><div class=cifras>{resumen}</div>{''.join(notas)}</div>
<div class=card><h2>Por {'día' if periodo == '30d' else 'hora'}</h2>{_grafico_horas(serie)}</div>
<div class=card><h2>Top destinos (ASN) por {e(orden_d)}</h2><p class=mut>Un ASN no es un servicio: Google, Meta, Akamai o Cloudflare
sirven cientos de servicios desde el mismo ASN. 0 = sin ASN / no público; -1 = otros agrupados.</p>{dest}</div>
<div class=card><h2>Puertos salientes (servicios que usan los abonados)</h2><p class=mut>Ordenado por % de abonados. Los puertos altos
sin catálogo van agrupados (1024-49151 y 49152-65535).</p>{_tabla_puertos(salientes)}</div>
<div class=card><h2>Puertos entrantes (servicios que exponen los abonados)</h2>{_tabla_puertos(entrantes)}</div>
<div class=card><h2>Puertos altos sin catálogo (exactos)</h2><p class=mut>Lo que el catálogo no nombra, por flujos.</p>{sin_cat}</div>
<div class=card><h2>Top consumidores por {e(orden_c)}</h2>{cons}</div>
<div class=card><h2>Por abonado y minuto (base para límites)</h2><p class=mut>Unidad: <b>por abonado y por minuto</b>, no por foto
como en el informe de conntrack. Un límite <code>dst-limit</code> se fija por encima del p99.9 con margen (×2), nunca en la mediana.</p>{pct}</div>
<div class=card><h2>Señales a revisar</h2><h3>Puertos sensibles (salientes)</h3>{_tabla_senal(sen.get('sensibles'))}
<h3>Posibles reflectores (UDP entrante)</h3>{_tabla_senal(sen.get('reflectores'))}
<h3>Barridos (≥ 50 destinos al mismo puerto en un minuto)</h3>{barridos}<h3>Posible P2P (≥ 100 pares UDP en un minuto)</h3>{p2p}</div>
<div class=card><h2>DNS: a qué resolvers preguntan</h2>{dns}</div>
<div class=card><h2>Destinos no públicos</h2><p class=mut>Redes privadas o reservadas fuera de la categoría: servicios internos del ISP,
rutas mal puestas o fugas.</p>{no_pub}</div>
<div class=card><h2>Salud del colector (últimas 24 h)</h2>{_salud(salud)}{vent}</div>
<div class=card><h2>Interfaces del router</h2>{intf}</div>"""
    return pagina("Tráfico", cuerpo, "/trafico", aviso=" ".join(avisos) or None)


def _datos_firewall(q):
    """Clasificación de la categoría para /firewall y la descarga. None si no hay base NetFlow."""
    F, con = _abrir_flujos()
    if con is None:
        return None
    inv = _inventario()
    try:
        routers = sorted(set(inv.get("routers", {})) | set(F.routers_con_datos(con)))
        categorias = sorted(set(F.categorias_con_datos(con))
                            | {c for r in inv.get("routers", {}).values() for c in r.get("categorias", {})})
        router, categoria, _, avisos = _filtros(q, routers, categorias)
        try:
            dias = int(q.get("dias") or 7)
            if not 1 <= dias <= 14:
                raise ValueError
        except ValueError:
            avisos.append(f"Días «{str(q.get('dias'))[:20]}» no válido (1 a 14): se usan 7.")
            dias = 7
        serv = F.servicios_categoria(con, categoria, router or None, dias)
        perc = F.percentiles_abonado(con, categoria, router or None, "7d")
    finally:
        con.close()
    return {"routers": routers, "categorias": categorias, "router": router, "categoria": categoria, "dias": dias,
            "avisos": avisos, "clasificacion": firewall.clasificar(serv, perc), "percentiles": perc}


def propuesta_firewall(q):
    """(nombre de archivo, texto .rsc) o None si no hay base NetFlow."""
    d = _datos_firewall(q)
    if d is None:
        return None
    texto = firewall.propuesta_rsc(d["clasificacion"], d["percentiles"], fecha=date.today().isoformat())
    return f"firewall-{d['categoria']}.rsc", texto


_TITULOS_CLASE = {"riesgo": "Riesgo", "esencial": "Esencial (no se bloquea)", "usado": "Usado", "minoritario": "Minoritario",
                  "no_observado": "No observado en el periodo"}


def vista_firewall(q):
    try:
        d = _datos_firewall(q)
    except (sqlite3.Error, ValueError, OSError) as err:
        return pagina("Firewall", f"<h1>Firewall por categoría</h1><div class=card><p class=bad>No se pudo leer la base NetFlow: "
                      f"{e(str(err))}</p></div>", "/firewall")
    if d is None:
        return pagina("Firewall", "<h1>Firewall por categoría</h1>" + SIN_NETFLOW, "/firewall")
    cl = d["clasificacion"]
    params = {"router": d["router"], "categoria": d["categoria"], "dias": d["dias"]}
    filtros = (f"<form method=get action='/firewall' class=filtros>"
               f"<label>Router{_selector('router', d['routers'], d['router'], 'Todos')}</label>"
               f"<label>Categoría{_selector('categoria', d['categorias'] or [d['categoria']], d['categoria'])}</label>"
               f"<label>Días (1-14)<input name=dias type=number min=1 max=14 value='{d['dias']}'></label>"
               "<button>Ver</button></form>")
    conteo = cl.get("conteo", {})
    cifras = "".join(_cifra(_TITULOS_CLASE[c], _num(conteo.get(c, 0)), "bad" if c == "riesgo" and conteo.get(c) else "")
                     for c in firewall.CLASES)
    if cl.get("suficiente"):
        estado = (f"<p class=ok>Evidencia suficiente: {_num(cl.get('dias_con_datos'))} días y {_num(cl.get('abonados_total'))} "
                  "abonados activos.</p>")
    else:
        estado = (f"<p class=warn>Evidencia insuficiente: {_t(cl.get('motivo_insuficiente'))}. La propuesta se puede descargar para "
                  "revisarla, pero su cabecera lo advierte: no aplicar sin más datos.</p>")
    tablas = []
    for c in firewall.CLASES:
        filas = [f for f in cl.get("filas", []) if f.get("clase") == c]
        if not filas:
            continue
        tabla = _tabla([("Sentido", False), ("Proto/puerto", False), ("Servicio", False), ("% abonados", True), ("Abonados", True),
                        ("Flujos", True), ("Bytes", True), ("Días observado", True), ("Motivo", False)],
                       [("ojo" if f.get("revisar") else "",
                         [_t(f.get("sentido")), _t(f.get("etiqueta")), _t(f.get("servicio")), _num(f.get("pct_decision")),
                          _num(f.get("abonados")), _num(f.get("flujos")), _b(f.get("bytes")), _num(f.get("dias_observado")),
                          _t(f.get("motivo")) + (" <b>revisar</b>" if f.get("revisar") else "")]) for f in filas])
        abierto = " open" if c in ("riesgo", "esencial") else ""
        tablas.append(f"<details{abierto}><summary>{_TITULOS_CLASE[c]} ({len(filas)})</summary>{tabla}</details>")
    texto = firewall.propuesta_rsc(cl, d["percentiles"], fecha=date.today().isoformat())
    descarga = f"/firewall/propuesta.rsc?{e(urlencode(params))}"
    cuerpo = f"""<h1>Firewall por categoría</h1>
<div class=card>{filtros}</div>
<div class=card><h2>Evidencia</h2><p class=mut>{e(d['categoria'])} · {e(', '.join(str(x) for x in cl.get('routers') or []) or 'todos los routers')} ·
{_t(cl.get('desde'))} a {_t(cl.get('hasta'))} · abonados distintos exactos del periodo.</p>{estado}<div class=cifras>{cifras}</div></div>
<div class=card><h2>Cómo se clasifica</h2><ul>
<li><b>Riesgo</b>: puerto de la lista de riesgo del sentido (SMTP 25, Telnet, SMB/NetBIOS/RPC, C2 Mēris salientes; reflectores UDP y
servicios de administración entrantes). Si lo usa ≥ {firewall.PCT_ESENCIAL:g} % de los abonados se marca <b>revisar</b>: masivo, decidir a mano.</li>
<li><b>Esencial</b>: de la lista «nunca bloquear» (web, QUIC, DNS, NTP, STUN, VPN de trabajo, correo de clientes, DNS cifrado = decisión de
política DNS) o usado por ≥ {firewall.PCT_ESENCIAL:g} % de los abonados.</li>
<li><b>Usado</b>: entre {firewall.PCT_USADO:g} % y {firewall.PCT_ESENCIAL:g} %. <b>Minoritario</b>: menos de {firewall.PCT_USADO:g} %.</li>
<li><b>No observado</b>: riesgo conocido o puerto del catálogo sin tráfico en el periodo.</li>
<li>Evidencia mínima: {firewall.MIN_DIAS} días con datos y {firewall.MIN_ABONADOS} abonados activos.</li></ul></div>
<div class=card><h2>Clasificación</h2>{''.join(tablas) or '<p class=mut>Sin servicios en el periodo.</p>'}</div>
<div class=card><h2>Propuesta (modo detección)</h2><p>Cada bloqueo nace como detección (address-list <code>DET-…</code>) con el drop gemelo
<code>disabled=yes</code>, solo para conexiones nuevas, sin IPs: la lista de la categoría la completa el operador. Despliegue: respaldo →
Safe Mode → un core canario → revisar contadores 7 días → activar drops → flota. Nada se aplica desde aquí.</p>
<p><a class=btn href="{descarga}">Descargar propuesta</a></p>
<details><summary>Ver propuesta</summary>{_copiable("fw-rsc", texto)}</details></div>"""
    return pagina("Firewall", cuerpo, "/firewall", aviso=" ".join(d["avisos"]) or None)


def vista_texto(titulo, ruta, activa, refresco=None):
    return pagina(titulo, f"<h1>{e(ruta.name)}</h1><div class=card><pre>{e(ruta.read_text(encoding='utf-8', errors='replace'))}</pre></div>",
                  activa, refresco=refresco)


DOC = """<h1>Documentación</h1>
<div class=card><h2>Qué hace</h2>
<p>Registra <b>todas</b> las conexiones de los abonados a partir de <b>NetFlow v9</b> (Traffic Flow) que envían los cores MikroTik, las
agrupa por router, categoría de abonado (residencial, empresarial…), sentido, servicio, destino (ASN) y abonado, y con eso clasifica cada
protocolo/puerto de la categoría y genera una propuesta de firewall para la cadena <code>forward</code> del core, en modo detección.</p>
<p>Las fotos de la tabla de <i>connection tracking</i> (conntrack) siguen funcionando y complementan: NetFlow da la <b>tasa</b> y la
cobertura completa (conexiones nuevas por minuto, % de abonados, destinos, consumo) → base de <code>dst-limit</code>; conntrack da la
<b>concurrencia</b> (conexiones abiertas a la vez) → base de <code>connection-limit</code>.</p></div>
<div class=card><h2>Seguridad sobre los routers</h2><ul>
<li>Solo se ejecutan órdenes <code>print</code>. El código rechaza cualquier otra antes de abrir SSH, y el usuario del router es del grupo <code>read</code>.</li>
<li>Antes de descargar se cuenta (<b>Contar</b>). Si un rango supera el máximo del inventario (150 000 conexiones por defecto) la muestra se omite: hay que partir el CIDR.</li>
<li>Este sistema no cambia nada en el router: Traffic Flow lo configura el operador con los comandos de <b>Panel → Exportar NetFlow</b>,
y la propuesta de firewall es un archivo <code>.rsc</code> para revisión humana.</li></ul></div>
<div class=card id="netflow"><h2>NetFlow: cómo se configura el router</h2><ol>
<li><b>Mirar antes</b> (<code>/ip traffic-flow print</code> y <code>target print</code>): si ya dice <code>enabled: yes</code>, el router
exporta a otro colector. <code>interfaces=</code> es <b>global</b>: cambiarlo cambia lo que recibe el otro sistema. Los comandos del panel lo
comprueban solos: en ese caso no tocan <code>interfaces=</code> y solo agregan el destino, salvo que sea <code>interfaces=all</code>
(el defecto, incluye la WAN): entonces no agregan nada y hay que acordar con el dueño del otro colector pasar a la interfaz de
clientes.</li>
<li><code>interfaces=</code> = la interfaz de clientes (si la VLAN va sobre un bridge, el bridge). Varias, separadas por coma; nombres con
espacios, toda la lista entre comillas. <b>Nunca la WAN</b>: multiplica el volumen y no aporta.</li>
<li><code>cache-entries=128k</code> (4k por defecto se llena en un core y parte los flujos; en equipos chicos 64k o 32k),
<code>active-flow-timeout=1m</code> (una conexión larga se reporta cada minuto, sus bytes caen en su minuto real).</li>
<li>Destino: este servidor, UDP 2055, versión 9, <code>src-address</code> = IP del router con la que este servidor lo ve,
<code>v9-template-timeout=1m</code>. Sin plantilla v9 el colector no decodifica nada: con poco tráfico puede tardar varios minutos.</li>
<li><b>Quitar</b> borra solo el destino hacia este servidor y apaga Traffic Flow únicamente si no queda otro colector.</li></ol>
<p>Servicios en el servidor: <code>mtp-colector</code> (nfcapd en UDP 2055, un archivo por router y minuto) y <code>mtp-flujos.timer</code>
(cada minuto procesa los archivos cerrados y los agrega en <code>data/flujos.db</code>).</p></div>
<div class=card><h2>Exportador desconocido</h2>
<p>El colector reconoce a cada router por la IP de origen del envío. Si llega desde una IP que no es la de ningún router (el envío sale por
NAT o VPN con otra IP), no se procesa y aparece en rojo en <b>Tráfico → Salud</b>: anotar esa IP en Routers → «IP desde la que exporta
NetFlow». Por eso dos routers no pueden tener la misma IP de exportación.</p></div>
<div class=card id="netflow-sentido"><h2>Subida, bajada y el caso «solo entrada»</h2>
<p>Subida = bytes que envía el abonado; bajada = bytes que recibe. La documentación de MikroTik no dice si Traffic Flow exporta lo que
entra, lo que sale o ambos por las interfaces listadas, y hay reportes de que solo exporta lo que <b>entra</b>. En ese caso, con la interfaz
de clientes se ven <b>todas las conexiones</b> que abre o contesta el abonado (alcanza para el firewall de salida), pero no la bajada: el
resumen lo avisa cuando la relación bajada/subida es menor que 0,5 o no hay subida. Para medirlo: comparar <code>/interface print stats</code>
de la interfaz de clientes con el minuto a minuto de Tráfico → Salud (elegir el router).</p></div>
<div class=card><h2>FastTrack y hw-offload</h2>
<p>El tráfico acelerado por hardware (FastTrack con <code>hw-offload=yes</code>, L3 HW offload del switch, bridge con <code>hw=yes</code>)
<b>no se exporta</b>. FastTrack por software está en duda (la documentación se contradice): si subida y bajada salen muy por debajo de los
contadores de la interfaz, es eso.</p></div>
<div class=card><h2>Página Tráfico: qué significa cada tabla</h2><ul>
<li><b>Abonado activo</b> = IP de la categoría con algún flujo en el periodo. En rangos públicos (empresarial) una IP que solo recibe
escaneos entrantes también cuenta: sube el total y baja los % de abonados (ver Página Firewall).</li>
<li><b>Filtros</b>: router (o todos: la misma IP en dos routers son dos abonados), categoría y periodo: <code>hoy</code>, <code>ayer</code>,
<code>7d</code> (los 7 días completos que terminan ayer) y <code>30d</code>.</li>
<li><b>Resumen</b>: abonados activos (exactos; en 30 días, máximo diario), flujos, subida, bajada, última ventana procesada, archivos
pendientes y exportadores desconocidos.</li>
<li><b>Por hora</b> (por día en 30 días): bajada y subida apiladas; el detalle de cada barra al pasar el ratón y en «Ver tabla».</li>
<li><b>Top destinos (ASN)</b>: por bytes o por abonados. Un ASN no es un servicio (las CDN sirven cientos desde el mismo ASN).</li>
<li><b>Puertos salientes y entrantes</b>: servicio, % de abonados que lo usaron, flujos y bytes. Los puertos altos sin catálogo se agrupan en
1024-49151 y 49152-65535; la tabla <b>sin catálogo</b> muestra los exactos más usados.</li>
<li><b>Top consumidores</b>: abonados por bajada, subida, total o flujos, con sus máximos por minuto.</li>
<li><b>Por abonado y minuto</b>: percentiles de conexiones nuevas, IP y puertos remotos, pares UDP, SYN sin respuesta. Unidad: <b>por
minuto</b> (no por foto como en conntrack). Error ≤ 10 %, siempre hacia arriba.</li>
<li><b>Señales</b>: puertos sensibles salientes (SMTP 25, Telnet, SMB…), posibles reflectores (UDP entrante a 53/123/1900…), barridos
(≥ 50 destinos al mismo puerto en un minuto) y P2P (≥ 100 pares UDP en un minuto). <b>DNS</b>: a qué resolvers preguntan.
<b>No públicos</b>: redes privadas fuera de la categoría.</li>
<li><b>Salud</b>: por exportador, archivos, flujos, % fuera de categoría (más de 30 %: ¿la WAN en <code>interfaces=</code>? ¿faltan
rangos?), secuencia perdida (se pierden paquetes del envío), errores, disco. <b>Interfaces</b>: ifIndex por donde pasa el tráfico.</li></ul></div>
<div class=card><h2>Retención</h2><ul>
<li>Crudo de nfcapd: 6 horas o 6 GB, lo que llegue antes (un guardián de disco borra antes si el disco se llena).</li>
<li>Presencia por abonado (para contar abonados distintos exactos): 8 a 14 días. Consumo por abonado y puertos exactos: 90 días.</li>
<li>Agregados diarios por servicio, destino e histogramas: 180 a 400 días.</li></ul></div>
<div class=card><h2>Página Firewall</h2>
<p>Clasifica cada proto/puerto de la categoría con el % de abonados distintos del periodo (1 a 14 días; 7 por defecto):</p><ul>
<li><b>Riesgo</b>: lista de riesgo del sentido (salientes: SMTP 25, Telnet 23/2323, RPC 135, NetBIOS 137-139, SMB 445, C2 Mēris
16464-16471; entrantes: reflectores UDP 53/123/1900/11211/19/389/161/5353 y Telnet, SMB, RDP, VNC, TR-069, Winbox, API). Con ≥ 5 % de
abonados queda en <b>revisar</b> (masivo: decidir a mano).</li>
<li><b>Esencial</b>: lista «nunca bloquear» (web, QUIC, DNS y NTP salientes, STUN, IPsec, OpenVPN, WireGuard, PPTP+GRE, correo de clientes,
DNS cifrado 853 = decisión de política DNS) o ≥ 5 % de los abonados. <b>Usado</b>: 0,5 % a 5 %. <b>Minoritario</b>: menos de 0,5 %.
<b>No observado</b>: riesgo conocido o puerto del catálogo sin tráfico.</li>
<li>Evidencia suficiente: 7 días con datos y 50 abonados activos. Si no, la página lo dice y la propuesta lo advierte en la cabecera.</li>
<li><b>Rangos públicos (empresarial)</b>: una IP del rango que solo <b>recibe</b> tráfico entrante (escaneos de internet) cuenta como
abonado activo aunque no la use nadie. Eso infla el total de abonados y baja los % de abonados de Tráfico y Firewall: un servicio
puede quedar como «usado» o «minoritario» siendo esencial para los clientes reales. Con rangos públicos, mirar también la cantidad de
abonados y no solo el %.</li>
<li><b>Descargar propuesta</b>: <code>.rsc</code> genérico, sin IPs, en modo detección (address-list <code>DET-RES-…</code>, drop gemelo
<code>disabled=yes</code>, solo <code>connection-state=new</code>, comentario con la evidencia) y su rollback. Lo mismo por consola:
<code>python3 -m mtp.firewall --datos /var/lib/mikrotik-traffic-profiler/data --categoria residencial</code>.</li></ul></div>
<div class=card><h2>Botones</h2><ul>
<li><b>Descubrir</b>: vuelca pools, direcciones, NAT, filtros, mangle, colas y ajustes de conntrack. Sirve para ubicar el punto de inserción.</li>
<li><b>Contar</b>: cuántas conexiones tiene ahora cada CIDR de la categoría, sin descargar nada.</li>
<li><b>Muestrear</b>: una foto de conntrack de la categoría (comprimida). Las fotos programadas son 4 seguidas cada 15 min.</li>
<li><b>Analizar</b>: genera el perfil con las muestras de los últimos 7 días. Corre también cada noche a las 23:30.</li></ul></div>
<div class=card><h2>Funcionamiento permanente</h2><ul>
<li>Cada router con su timer activo se muestrea todos los días, sin fecha de fin.</li>
<li>Cada noche sale un informe nuevo con la ventana móvil de 7 días: comparando informes se ve cómo cambia el uso.</li>
<li>Retención: las muestras crudas y los logs de tareas se borran a los 14 días; los informes se guardan siempre.</li></ul></div>
<div class=card><h2>Programación</h2>
<p>El timer <code>mtp-recolectar.timer</code> muestrea todos los routers con <b>Muestreo automático</b> activado: franjas 09:00, 15:00,
20:30 y 21:30 (hora de Ecuador), 4 muestras cada 15 min por franja. Una semana en todas las franjas es la base mínima para diseñar.</p></div>
<div class=card><h2>Agregar un router</h2><ol>
<li>En el router: pegar los comandos de la tarjeta <b>Conectar un router</b> del Panel (RouterOS 7 o 6). Crean el usuario
<code>trafico</code> del grupo <code>read</code>, limitado a la IP de este servidor, con la llave de este servidor y sin clave.</li>
<li>Pestaña <b>Routers</b> → formulario: nombre, IP y puerto SSH, rangos residenciales y empresariales y, si el router exporta NetFlow
desde otra IP, esa IP.</li>
<li>Panel → <b>Probar conexión</b> (debe salir la identidad y la versión del router) → <b>Descubrir</b> y <b>Contar</b>.</li>
<li>Si todo cuadra, en Routers → <b>Activar muestreo</b>. Desde ahí se muestrea solo en cada franja.</li>
<li>NetFlow: Panel → <b>Exportar NetFlow</b>, elegir el router y la interfaz de clientes, y pasar los comandos al operador. En menos de
tres minutos el router debe aparecer en <b>Tráfico → Salud</b> con archivos por minuto.</li></ol></div>
<div class=card><h2>Cómo leer el informe</h2><ul>
<li>Pesa el <b>% de abonados</b>, no los bytes: lo que usa mucha gente no se bloquea.</li>
<li>Lo muy corto (DNS, NTP) sale poco en una foto: su ausencia no prueba que nadie lo use.</li>
<li>Los límites por abonado se fijan por encima del <b>p99.9</b> con margen, nunca en la mediana.</li>
<li>Señales: SMTP 25 directo, SMB/NetBIOS/RPC, Telnet, barridos (≥50 destinos al mismo puerto) y abonados que reciben UDP de servicios amplificables.</li></ul></div>
<div class=card><h2>Del perfil al firewall</h2>
<p>Modelo residencial: <b>lista negra con evidencia</b>, no lista blanca. Capa <code>RES-SALIDA</code>/<code>RES-ENTRADA</code> solo para conexiones nuevas;
cada bloqueo nace en modo detección (address-list <code>DET-RES-*</code>) con el drop gemelo desactivado, se revisa 7 días y se activa primero en un core canario.
La base es la página <b>Firewall</b> (NetFlow); el agente <code>trafico-mikrotik</code> la revisa, le suma el <code>connection-limit</code> de
conntrack y redacta la lectura en <code>propuestas/</code> del repositorio.</p></div>
<div class=card><h2>Archivos en el servidor</h2><ul>
<li>Código: <code>/opt/mikrotik-traffic-profiler</code> (repositorio git; actualizar con <code>git pull</code> y reiniciar <code>mtp-web</code>).</li>
<li>Configuración: <code>/etc/mikrotik-traffic-profiler/</code> (inventario, web.json con el hash de la clave del panel, mtp.env con el puerto
y los límites de NetFlow).</li>
<li>Datos: <code>/var/lib/mikrotik-traffic-profiler/data/</code> (crudo, descubrimiento, informes, tareas; <code>nfcapd/</code> = archivos
NetFlow crudos por exportador; <code>flujos.db</code> = agregados NetFlow).</li>
<li>Clave del panel: <code>python3 -m mtp.web --config /etc/mikrotik-traffic-profiler/web.json --cambiar-clave</code> como root desde /opt/mikrotik-traffic-profiler.</li></ul></div>
"""

LOGIN = """<!doctype html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Entrar · Perfil de tráfico</title><style>{css}</style></head><body><main style="max-width:360px;margin-top:12vh">
<div class=card><h1>Perfil de tráfico MikroTik</h1>{error}<form method="post" action="/entrar">
<label>Usuario<input name="usuario" autocomplete="username" autofocus></label>
<label>Clave<input name="clave" type="password" autocomplete="current-password"></label><button>Entrar</button></form></div></main></body></html>"""


# ---------- servidor ----------

class Manejador(BaseHTTPRequestHandler):
    server_version = "mtp"
    sys_version = ""

    def log_message(self, formato, *args):
        sys.stderr.write(f"{self.client_address[0]} {formato % args}\n")

    def _usuario(self):
        c = SimpleCookie(self.headers.get("Cookie", ""))
        return sesion_valida(c["mtp_sesion"].value, CFG["secreto"]) if "mtp_sesion" in c else None

    def _enviar(self, codigo, cuerpo, cabeceras=None, tipo="text/html; charset=utf-8"):
        datos = cuerpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", tipo)
        self.send_header("Content-Length", str(len(datos)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        for k, v in (cabeceras or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(datos)

    def _ir(self, destino, cabeceras=None):
        self.send_response(303)
        self.send_header("Location", destino)
        for k, v in (cabeceras or {}).items():
            self.send_header(k, v)
        self.end_headers()

    def _form(self):
        largo = min(int(self.headers.get("Content-Length", 0) or 0), 10_000)
        return {k: v[0] for k, v in parse_qs(self.rfile.read(largo).decode("utf-8", "replace")).items()}

    def do_GET(self):
        url = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(url.query).items()}
        if url.path == "/entrar":
            return self._enviar(200, LOGIN.format(css=CSS, error=""))
        if not self._usuario():
            return self._ir("/entrar")
        if url.path == "/":
            return self._enviar(200, vista_panel(q.get("aviso"), q.get("nf_router"), q.get("nf_interfaz")))
        if url.path == "/trafico":
            return self._enviar(200, vista_trafico(q))
        if url.path == "/firewall":
            return self._enviar(200, vista_firewall(q))
        if url.path == "/firewall/propuesta.rsc":
            try:
                propuesta = propuesta_firewall(q)
            except (sqlite3.Error, ValueError, OSError) as err:
                return self._enviar(500, pagina("Error", f"<h1>No se pudo leer la base NetFlow</h1><p>{e(str(err))}</p>"))
            if propuesta is None:
                return self._enviar(404, pagina("Sin datos", "<h1>Firewall por categoría</h1>" + SIN_NETFLOW, "/firewall"))
            nombre, texto = propuesta
            return self._enviar(200, texto, {"Content-Disposition": f'attachment; filename="{nombre}"'},
                                tipo="text/plain; charset=utf-8")
        if url.path == "/muestras":
            return self._enviar(200, vista_muestras())
        if url.path == "/informes":
            return self._enviar(200, vista_informes())
        if url.path == "/doc":
            return self._enviar(200, pagina("Documentación", DOC, "/doc"))
        if url.path == "/routers":
            return self._enviar(200, vista_routers(q.get("editar"), q.get("aviso")))
        rutas = {"/informe": ("informes", r"^[\w.-]+\.json$"), "/lectura": ("informes", r"^[\w.-]+-lectura\.md$"),
                 "/descubrimiento": ("descubrimiento", r"^[\w.-]+\.txt$"), "/tarea": ("tareas", r"^[\w.-]+\.log$")}
        if url.path in rutas:
            carpeta, patron = rutas[url.path]
            ruta = archivo_seguro(_datos(carpeta), q.get("f"), patron)
            if not ruta:
                return self._enviar(404, pagina("No encontrado", "<h1>No encontrado</h1>"))
            if url.path == "/informe":
                return self._enviar(200, vista_informe(ruta))
            p = TAREAS.get(ruta.name)
            en_curso = url.path == "/tarea" and p is not None and p.poll() is None
            activa = "/" if url.path == "/tarea" else ("/informes" if url.path == "/lectura" else "/muestras")
            return self._enviar(200, vista_texto(ruta.name, ruta, activa, refresco=5 if en_curso else None))
        return self._enviar(404, pagina("No encontrado", "<h1>No encontrado</h1>"))

    def do_POST(self):
        url = urlparse(self.path)
        ip = self.client_address[0]
        f = self._form()  # leer siempre el cuerpo: responder sin leerlo corta la conexión
        if url.path == "/entrar":
            fallos, hasta = _FALLOS.get(ip, (0, 0))
            if hasta > time.time():
                return self._enviar(429, LOGIN.format(css=CSS, error="<p class=bad>Demasiados intentos. Espera 15 minutos.</p>"))
            if f.get("usuario") == CFG["usuario"] and verificar_clave(f.get("clave", ""), CFG["hash"]):
                _FALLOS.pop(ip, None)
                cookie = f"mtp_sesion={firmar(CFG['usuario'], CFG['secreto'])}; HttpOnly; SameSite=Strict; Path=/; Max-Age={SESION_HORAS * 3600}"
                return self._ir("/", {"Set-Cookie": cookie})
            fallos += 1
            _FALLOS[ip] = (0, time.time() + 900) if fallos >= 5 else (fallos, 0)
            return self._enviar(401, LOGIN.format(css=CSS, error="<p class=bad>Usuario o clave incorrectos.</p>"))
        if url.path == "/salir":
            return self._ir("/entrar", {"Set-Cookie": "mtp_sesion=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"})
        if not self._usuario():
            return self._ir("/entrar")
        origen = self.headers.get("Origin")
        if origen and urlparse(origen).netloc != self.headers.get("Host"):
            return self._enviar(403, pagina("Prohibido", "<h1>Origen no permitido</h1>"))
        if url.path.startswith("/routers/"):
            return self._ir("/routers?aviso=" + quote(self._routers(url.path, f)))
        if url.path == "/accion":
            accion, router, categoria = f.get("accion"), f.get("router") or None, f.get("categoria") or None
            inv = _inventario()
            if accion not in {"probar", "descubrir", "contar", "recolectar", "analizar"}:
                msg = "Acción desconocida."
            elif accion != "analizar" and router not in inv.get("routers", {}):
                msg = "Ese router no está en el inventario."
            elif accion in {"contar", "recolectar"} and categoria not in inv["routers"][router].get("categorias", {}):
                msg = "Esa categoría no existe en el router."
            elif accion == "analizar" and not (categoria and re.match(r"^[\w-]+$", categoria)):
                msg = "Categoría inválida."
            else:
                msg = lanzar(accion, router if accion != "analizar" else None, categoria)
            return self._ir("/?aviso=" + quote(msg))
        return self._enviar(404, pagina("No encontrado", "<h1>No encontrado</h1>"))

    def _routers(self, ruta, f):
        """Alta, edición, borrado y pausa de routers. Devuelve el mensaje para el modal."""
        with _CANDADO:
            inv = _inventario()
            nombre = f.get("nombre", "")
            if ruta == "/routers/guardar":
                try:
                    nuevo, router = inventario.router_desde_form(f)
                except ValueError as err:
                    return str(err)
                anterior = f.get("anterior") or ""
                if nuevo != anterior and nuevo in inv["routers"]:
                    return f"Ya existe un router llamado «{nuevo}»."
                # el colector reconoce al router por la IP de origen del envío NetFlow: no puede repetirse
                ip_nf = router.get("exportador") or router["host"]
                for otro, r in inv["routers"].items():
                    if otro not in (nuevo, anterior) and (r.get("exportador") or r.get("host")) == ip_nf:
                        return (f"La IP de exportación NetFlow {ip_nf} ya es la de «{otro}»: el colector no podría distinguirlos. "
                                "Si este router envía desde otra IP, anotarla en «IP desde la que exporta NetFlow».")
                if anterior and anterior != nuevo:
                    inv["routers"].pop(anterior, None)
                existia = nuevo in inv["routers"] or bool(anterior)
                inv["routers"][nuevo] = router
                inventario.guardar(CFG["inventario"], inv)
                return f"Router «{nuevo}» {'actualizado' if existia else 'agregado'}. Siguiente paso: Probar conexión en el Panel."
            if nombre not in inv["routers"]:
                return "Ese router no está en el inventario."
            if ruta == "/routers/borrar":
                del inv["routers"][nombre]
                inventario.guardar(CFG["inventario"], inv)
                return f"Router «{nombre}» eliminado. Sus muestras guardadas se conservan hasta la limpieza de 14 días."
            if ruta == "/routers/activo":
                inv["routers"][nombre]["activo"] = f.get("activo") == "on"
                inventario.guardar(CFG["inventario"], inv)
                return f"Muestreo de «{nombre}» {'activado' if inv['routers'][nombre]['activo'] else 'en pausa'}."
        return "Acción desconocida."


def main():
    p = argparse.ArgumentParser(description="Panel web del perfilador de tráfico.")
    p.add_argument("--config", required=True, type=Path)
    p.add_argument("--inventario", default=str(RAIZ / "inventario.json"))
    p.add_argument("--datos", default=str(RAIZ / "data"))
    p.add_argument("--llave-publica", default="")
    p.add_argument("--ip-origen", default=os.environ.get("IP_ORIGEN") or None,
                   help="IP con la que los routers ven a este servidor (por defecto, la de salida)")
    p.add_argument("--escuchar", default="0.0.0.0")
    p.add_argument("--puerto", type=int, default=8080)
    p.add_argument("--cambiar-clave", action="store_true", help="lee la clave nueva de stdin y guarda su hash")
    a = p.parse_args()

    if a.cambiar_clave:
        clave = sys.stdin.readline().rstrip("\n")
        if len(clave) < 12:
            sys.exit("la clave debe tener al menos 12 caracteres")
        conf = json.loads(a.config.read_text()) if a.config.exists() else {"usuario": "admin", "secreto": secrets.token_hex(32)}
        conf["hash"] = hash_clave(clave)
        conf["secreto"] = secrets.token_hex(32)  # cierra las sesiones abiertas
        a.config.write_text(json.dumps(conf, indent=2))
        print(f"clave actualizada en {a.config}")
        return

    CFG.update(json.loads(a.config.read_text()))
    CFG.update(inventario=a.inventario, datos=a.datos, llave_publica=a.llave_publica, ip_origen=a.ip_origen or ip_origen())
    servidor = ThreadingHTTPServer((a.escuchar, a.puerto), Manejador)
    print(f"panel en http://{a.escuchar}:{a.puerto}", flush=True)
    servidor.serve_forever()


if __name__ == "__main__":
    main()
