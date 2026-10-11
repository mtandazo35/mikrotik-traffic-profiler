"""Panel web: ver muestras, informes y actividad; lanzar acciones de solo lectura sobre los routers.

  python3 -m mtp.web --config /etc/mikrotik-traffic-profiler/web.json --inventario … --datos … [--puerto 8080]
  python3 -m mtp.web --config … --cambiar-clave          (lee la clave nueva de stdin)
"""
import argparse
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse

RAIZ = Path(__file__).resolve().parent.parent
ITERACIONES = 600_000
SESION_HORAS = 8
CFG = {}
TAREAS = {}  # nombre de log -> Popen
_FALLOS = {}  # ip -> (fallos, bloqueado_hasta)
_CANDADO = threading.Lock()


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
        return json.loads(Path(CFG["inventario"]).read_text(encoding="utf-8"))
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
.copiable{position:relative}.copiable button{position:absolute;top:6px;right:6px}.copiable pre{padding-right:80px;white-space:pre-wrap;word-break:break-all}
dialog{border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);max-width:520px}dialog::backdrop{background:#0008}
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
                  [("/", "Panel"), ("/muestras", "Muestras"), ("/informes", "Informes"), ("/doc", "Documentación")])
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


def vista_panel(aviso=None):
    inv = _inventario()
    muestras = _manifiestos()
    filas = []
    for nombre, r in inv.get("routers", {}).items():
        propias = [m for m in muestras if m.get("router") == nombre]
        ultima = propias[0] if propias else {}
        cats = r.get("categorias", {})
        rangos = "<br>".join(f"{e(c)}: {e(', '.join(v))}" for c, v in cats.items())
        acciones = _boton("descubrir", "Descubrir", nombre, sec=True)
        for c in cats:
            acciones += _boton("contar", f"Contar {e(c)}", nombre, c, sec=True)
            acciones += _boton("recolectar", f"Muestrear {e(c)}", nombre, c,
                               confirmar=f"Tomar una muestra de conntrack de {c} en {nombre} (solo lectura)?")
        filas.append(
            f"<tr><td><b>{e(nombre)}</b><div class='mut'>{e(r.get('host', ''))}:{e(str(r.get('puerto', 22)))}</div></td>"
            f"<td>{rangos}</td>"
            f"<td class='n'>{len(propias)}</td><td>{e(ultima.get('ts', '—'))}"
            f"{'<div class=warn>' + e(ultima['omitida']) + '</div>' if ultima.get('omitida') else ''}</td>"
            f"<td>{acciones}</td></tr>")
    routers = ("<table><tr><th>Router</th><th>Categorías (CIDR)</th><th class=n>Muestras</th><th>Última</th>"
               "<th>Acciones (solo lectura)</th></tr>" + "".join(filas) + "</table>") if filas else (
        "<p class='mut'>Aún no hay routers en el inventario. Se agregan en "
        f"<code>{e(CFG['inventario'])}</code> (ver Documentación).</p>")
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
    return pagina("Panel", f"""
<h1>Panel</h1>
<div class=card><h2>Routers</h2>{routers}</div>
<div class=card><h2>Análisis</h2><p class=mut>Genera el perfil con las muestras de los últimos 7 días. También corre solo cada noche a las 23:30.</p>{analizar}</div>
<div class=card><h2>Tareas recientes</h2>{'<table>' + ''.join(tareas) + '</table>' if tareas else '<p class=mut>Sin tareas todavía.</p>'}</div>
<div class=card><h2>Programación (systemd)</h2><pre>{e(_timers())}</pre></div>
<div class=card><h2>Conectar un router</h2>{conectar}</div>
""", "/", aviso=aviso)


def _copiable(ident, texto):
    return (f'<div class=copiable><button class=sec data-id="{ident}" onclick="copiar(this.dataset.id, this)">Copiar</button>'
            f'<pre id="{ident}">{e(texto)}</pre></div>')


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


def vista_texto(titulo, ruta, activa, refresco=None):
    return pagina(titulo, f"<h1>{e(ruta.name)}</h1><div class=card><pre>{e(ruta.read_text(encoding='utf-8', errors='replace'))}</pre></div>",
                  activa, refresco=refresco)


DOC = """<h1>Documentación</h1>
<div class=card><h2>Qué hace</h2>
<p>Toma fotos de la tabla de <i>connection tracking</i> de los cores MikroTik, filtradas por el rango de cada categoría de abonado
(residencial, empresarial…), y arma un perfil: qué puertos y protocolos usan, hacia qué destinos (ASN), en qué sentido y cuántas
conexiones abre cada abonado. Con ese perfil se diseña el firewall de la categoría en la cadena <code>forward</code> del core.</p></div>
<div class=card><h2>Seguridad sobre los routers</h2><ul>
<li>Solo se ejecutan órdenes <code>print</code>. El código rechaza cualquier otra antes de abrir SSH, y el usuario del router es del grupo <code>read</code>.</li>
<li>Antes de descargar se cuenta (<b>Contar</b>). Si un rango supera el máximo del inventario (150 000 conexiones por defecto) la muestra se omite: hay que partir el CIDR.</li>
<li>No se activa Traffic Flow, ni torch, ni se cambia ninguna regla. La propuesta de firewall es un archivo para revisión humana.</li></ul></div>
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
<p>Por router se habilita <code>mtp-recolectar@&lt;router&gt;.timer</code>: franjas 09:00, 15:00, 20:30 y 21:30 (hora de Ecuador),
4 muestras cada 15 min por franja. Una semana en todas las franjas es la base mínima para diseñar.</p></div>
<div class=card><h2>Agregar un router</h2><ol>
<li>En el router: pegar los comandos de la tarjeta <b>Conectar un router</b> del Panel (RouterOS 7 o 6). Crean el usuario
<code>trafico</code> del grupo <code>read</code>, limitado a la IP de este servidor, con la llave de este servidor y sin clave.</li>
<li>En el servidor: agregarlo a <code>/etc/mikrotik-traffic-profiler/inventario.json</code> con host, puerto, usuario <code>trafico</code> y los CIDR de cada categoría.</li>
<li>Panel → Descubrir y Contar. Si todo cuadra: <code>systemctl enable --now mtp-recolectar@&lt;router&gt;.timer</code>.</li></ol></div>
<div class=card><h2>Cómo leer el informe</h2><ul>
<li>Pesa el <b>% de abonados</b>, no los bytes: lo que usa mucha gente no se bloquea.</li>
<li>Lo muy corto (DNS, NTP) sale poco en una foto: su ausencia no prueba que nadie lo use.</li>
<li>Los límites por abonado se fijan por encima del <b>p99.9</b> con margen, nunca en la mediana.</li>
<li>Señales: SMTP 25 directo, SMB/NetBIOS/RPC, Telnet, barridos (≥50 destinos al mismo puerto) y abonados que reciben UDP de servicios amplificables.</li></ul></div>
<div class=card><h2>Del perfil al firewall</h2>
<p>Modelo residencial: <b>lista negra con evidencia</b>, no lista blanca. Capa <code>RES-SALIDA</code>/<code>RES-ENTRADA</code> solo para conexiones nuevas;
cada bloqueo nace en modo detección (address-list <code>DET-RES-*</code>) con el drop gemelo desactivado, se revisa 7 días y se activa primero en un core canario.
La propuesta la redacta el agente <code>trafico-mikrotik</code> en <code>propuestas/</code> del repositorio.</p></div>
<div class=card><h2>Archivos en el servidor</h2><ul>
<li>Código: <code>/opt/mikrotik-traffic-profiler</code> (repositorio git; actualizar con <code>git pull</code> y reiniciar <code>mtp-web</code>).</li>
<li>Configuración: <code>/etc/mikrotik-traffic-profiler/</code> (inventario, web.json con el hash de la clave del panel).</li>
<li>Datos: <code>/var/lib/mikrotik-traffic-profiler/data/</code> (crudo, descubrimiento, informes, tareas).</li>
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

    def _enviar(self, codigo, cuerpo, cabeceras=None):
        datos = cuerpo.encode("utf-8")
        self.send_response(codigo)
        self.send_header("Content-Type", "text/html; charset=utf-8")
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
            return self._enviar(200, vista_panel(q.get("aviso")))
        if url.path == "/muestras":
            return self._enviar(200, vista_muestras())
        if url.path == "/informes":
            return self._enviar(200, vista_informes())
        if url.path == "/doc":
            return self._enviar(200, pagina("Documentación", DOC, "/doc"))
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
        if url.path == "/accion":
            accion, router, categoria = f.get("accion"), f.get("router") or None, f.get("categoria") or None
            inv = _inventario()
            if accion not in {"descubrir", "contar", "recolectar", "analizar"}:
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
