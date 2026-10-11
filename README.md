# mikrotik-traffic-profiler

Perfil de tráfico por **categoría de abonado** (residencial, empresarial…) en cores MikroTik de ISP, para
diseñar el firewall de cada categoría con evidencia y no a ojo.

- **Fuente principal: NetFlow v9** (Traffic Flow de RouterOS 6.49 y 7.x). Cada core envía un registro de cada
  conexión de los abonados a un colector `nfcapd` en este servidor; un procesador los agrega cada minuto por
  router, categoría, sentido, servicio, destino (ASN) y abonado. Ve **todas** las conexiones, no fotos.
- **Complemento: conntrack por SSH, solo `print`** (una guarda en código rechaza cualquier otra orden). Las fotos
  dan la **concurrencia** (conexiones abiertas a la vez) que NetFlow no da: base de `connection-limit`. NetFlow da
  la **tasa** (conexiones nuevas por minuto): base de `dst-limit`.
- Clasifica cada protocolo/puerto de la categoría (esencial, usado, minoritario, riesgo, no observado) con el %
  de abonados distintos y genera una propuesta de firewall `.rsc` **en modo detección**, sin IPs.
- **El sistema no cambia nada en los routers.** La configuración de Traffic Flow sale como comandos para que los
  pegue el operador (Panel → Exportar NetFlow) y el firewall como archivo para revisión humana.
- Python 3.10+ solo con la biblioteca estándar, más `nfdump` de Debian para el colector.

El agente de Claude Code `trafico-mikrotik` (`.claude/agents/trafico-mikrotik.md`) consulta los datos, interpreta
el perfil y redacta la capa de firewall de la categoría (`propuestas/`), siempre en fase de detección primero.
El diseño completo de la parte NetFlow está en `docs/diseno-netflow.md`.

## Arquitectura

```
cores MikroTik ──NetFlow v9, UDP 2055──▶ mtp-colector (nfcapd, un archivo por router y minuto)
                                              │ data/nfcapd/<ip-exportador>/nfcapd.AAAAmmddHHMM
                                              ▼
                                 mtp-flujos.timer (cada minuto, streaming, tope de memoria)
                                              │ agrega y descarta el crudo
                                              ▼
                                   data/flujos.db (SQLite) ──▶ mtp-web: Tráfico, Firewall
cores MikroTik ◀──SSH solo print── mtp-recolectar.timer (conntrack) ──▶ mtp-analizar.timer ──▶ Informes
```

## Servidor con panel web

```sh
apt-get install -y git
git clone https://github.com/mtandazo35/mikrotik-traffic-profiler /opt/mikrotik-traffic-profiler
bash /opt/mikrotik-traffic-profiler/deploy/install.sh            # --puerto 8080 por defecto
```

Deja: usuario de servicio `mtp`; llave RSA 4096 para los routers (RouterOS 6 no acepta ed25519) en
`/var/lib/mikrotik-traffic-profiler/.ssh/`; configuración en `/etc/mikrotik-traffic-profiler/` (
`mtp.env`, `web.json` con la clave del panel en PBKDF2); datos en `/var/lib/mikrotik-traffic-profiler/data/`.
La clave del panel se muestra una sola vez; se cambia con
`python3 -m mtp.web --config /etc/mikrotik-traffic-profiler/web.json --cambiar-clave` (lee de stdin).

Servicios:

| Unidad | Qué hace |
|---|---|
| `mtp-web` | Panel (puerto 8080). |
| `mtp-colector` | `nfcapd` en **UDP 2055**, usuario `mtp`, un subdirectorio por exportador, archivos de 60 s. El `nfdump@default` que trae el paquete de Debian queda desactivado (chocaría con el puerto). |
| `mtp-flujos.timer` | Cada minuto procesa los archivos NetFlow cerrados, cierra los días y aplica retención y el guardián de disco. |
| `mtp-recolectar.timer` | Fotos de conntrack de los routers con muestreo activo (09:00, 15:00, 20:30, 21:30; 4 muestras cada 15 min). |
| `mtp-analizar.timer` | Informe de conntrack de 7 días (23:30). |

Puertos: TCP 8080 (panel) y UDP 2055 (NetFlow, variable `PUERTO_NETFLOW` de `mtp.env`). Cualquiera que alcance
el UDP 2055 aparece como **exportador desconocido** y se descarta; cerrar el puerto a las IP del inventario es
una decisión aparte.

El panel muestra routers, **Tráfico** (NetFlow por categoría, router y periodo: resumen, serie por hora, destinos
ASN, puertos salientes y entrantes con % de abonados, puertos sin catálogo, consumidores, percentiles por
abonado y minuto, señales, DNS, salud del colector), **Firewall** (clasificación con su evidencia y descarga de
la propuesta `.rsc`), muestras, informes de conntrack, tareas y timers, y su apartado de Documentación. Actualizar:
`git -C /opt/mikrotik-traffic-profiler pull && systemctl restart mtp-web`.

## Configurar NetFlow en un router

Panel → **Exportar NetFlow**: elegir el router (su IP va en `src-address`) y la interfaz de clientes, y pasar los
comandos al operador. Qué hacen:

1. Miran si el router ya exporta a otro colector. `interfaces=` es global: si Traffic Flow ya estaba activo con
   interfaces concretas, no se cambia y solo se agrega el destino; si está en `interfaces=all` (el defecto, incluye
   la WAN) **no se agrega nada** y hay que acordar con el dueño del otro colector pasar a la interfaz de clientes.
2. `interfaces=` la interfaz de clientes (nunca la WAN; nombres con espacios entre comillas),
   `cache-entries=128k`, `active-flow-timeout=1m`; destino `IP_DEL_SERVIDOR:2055` versión 9 con
   `src-address` = IP del router y `v9-template-timeout=1m` (con poco tráfico la plantilla puede tardar minutos).
3. Quitar borra solo nuestro destino y apaga Traffic Flow únicamente si no queda otro colector.

Si el envío llega desde otra IP (NAT, VPN), anotarla en Routers → «IP desde la que exporta NetFlow»: el colector
reconoce cada router por esa IP, así que no puede repetirse entre routers.

## Uso del CLI

```sh
cp inventario.example.json inventario.json   # completar routers, acceso y CIDR por categoría
# conntrack (solo print)
python trafico.py descubrir  --router core-a                 # pools, NAT, filtros, conntrack
python trafico.py contar     --router core-a --categoria residencial
python trafico.py recolectar --router core-a --categoria residencial --repetir 4 --intervalo 15
python trafico.py asn                                       # baja/refresca la tabla IP→ASN (>7 días)
python trafico.py analizar   --categoria residencial --ip2asn data/ip2asn-v4.tsv.gz
# NetFlow
python trafico.py flujos-estado                             # salud del colector (JSON)
python trafico.py flujos-consulta top_puertos --categoria residencial --periodo 7d
python -m mtp.firewall --datos data --categoria residencial [--router core-a] [--dias 7] [--salida f.rsc] [--forzar]
```

`mtp.firewall` sale con código 1 si la evidencia no alcanza (menos de 7 días con datos o de 50 abonados
activos), salvo `--forzar`; entonces la cabecera de la propuesta lo advierte. `--limite-conexiones N` añade el
`connection-limit` (N = 2 × p99.9 del informe de conntrack).

Acceso SSH: `transporte: "ssh"` usa OpenSSH con llave (`BatchMode`); `transporte: "plink"` usa PuTTY con la
clave en la variable de entorno que nombre `password_env`. La clave nunca va en el inventario. Lo ideal es un
usuario del grupo `read` limitado por `address=` a la IP desde donde se recolecta.

Todo lo que sale de los routers queda en `data/` (ignorado por git): `crudo/<router>/<categoria>/` con un
`muestras.jsonl` por carpeta, `descubrimiento/`, `informes/`, `nfcapd/` (NetFlow crudo) y `flujos.db`.

## Clasificación y propuesta de firewall

| Clase | Regla (en este orden) |
|---|---|
| riesgo | proto/puerto de la lista de riesgo del sentido: salientes tcp 25, 23, 2323, 135, 139, 445, udp 137, 138, tcp 16464-16471; entrantes udp 53, 123, 1900, 11211, 19, 389, 161, 5353 y tcp 23, 2323, 135, 139, 445, 3389, 5900, 7547, 8291, 8728. Con ≥ 5 % de abonados se marca **revisar** (masivo: decidir a mano). |
| esencial | lista «nunca bloquear» (web, QUIC, DNS y NTP salientes, STUN, IPsec, OpenVPN, WireGuard, PPTP+GRE, correo de clientes, 853 = decisión de política DNS) o ≥ 5 % de los abonados |
| usado | 0,5 % a 5 % |
| minoritario | < 0,5 % |
| no observado | riesgo conocido o puerto del catálogo sin tráfico en el periodo |

El % se calcula con abonados distintos exactos del periodo (1 a 14 días; 7 por defecto). La propuesta: capa
`RES-SALIDA`/`RES-ENTRADA` en `forward` solo para `connection-state=new`, cada riesgo observado como pareja
detección (`add-src-to-address-list` a `DET-RES-…`) + drop `disabled=yes` con la evidencia en el comentario,
ráfaga `dst-limit` = 2 × p99.9 de conexiones TCP nuevas por minuto, entrantes nuevos sin dst-nat en detección, y
el rollback. Los riesgos masivos y los no observados van solo comentados.

## Retención y disco

| Dato | Retención |
|---|---|
| Crudo nfcapd | 6 h o 6 GB, lo que llegue antes (`CRUDO_HORAS`, `CRUDO_MAX_GB`) |
| Presencia por abonado (abonados distintos exactos) | 8–14 días |
| Consumo por abonado, puertos exactos, señales | 90 días |
| Agregados diarios por servicio, destino, histogramas | 180–400 días |
| Muestras de conntrack y logs de tareas | 14 días (los informes se guardan siempre) |

Un guardián de disco borra crudo ya procesado si el disco baja del 15 % libre y, por debajo del 8 %, también
crudo sin procesar (queda registrado como descartado). El procesador tiene tope de memoria (`MemoryMax=750M`) y
aborta un archivo con demasiadas claves en vez de crecer.

## Límites conocidos

- **Solo entrada (por confirmar en cada router)**: hay reportes de que Traffic Flow solo exporta lo que entra
  por las interfaces listadas. Con la interfaz de clientes se ven todas las conexiones, pero no la bajada; el
  panel lo avisa cuando la relación bajada/subida es menor que 0,5.
- **hw-offload** (FastTrack por hardware, L3 HW offload, bridge `hw=yes`): ese tráfico no se exporta. FastTrack
  por software está en duda; se mide comparando con los contadores de la interfaz (Tráfico → Salud).
- La WAN en `interfaces=` multiplica el volumen: el panel avisa con más de 30 % de flujos fuera de categoría.
- NetFlow no ve dominios, contenido ni el equipo detrás del CPE; un ASN de CDN sirve cientos de servicios.
- Solo IPv4. Abonados distintos en 30 días = máximo diario (en 7 días son exactos).
- Las fotos de conntrack subrepresentan lo muy corto (DNS, NTP) y con FastTrack por hardware sus bytes no avanzan.

## Pruebas

```sh
python -m unittest discover -s tests -t . -v
```
