# mikrotik-traffic-profiler

Perfil de tráfico por **categoría de abonado** (residencial, empresarial…) en cores MikroTik de ISP, para
diseñar el firewall de cada categoría con evidencia y no a ojo.

- Lee la tabla de connection tracking por SSH, **solo `print`** (una guarda en código rechaza cualquier otra
  orden). No cambia nada en el router: ni Traffic Flow, ni torch, ni reglas.
- Filtra en el router por el rango de la categoría y descarga solo eso, con tope de conexiones por CIDR
  (`contar` antes de bajar nada). Así no hay que imprimir la tabla entera de un core con CGNAT.
- Agrega por puerto/protocolo, destino (ASN con el TSV público de iptoasn.com, sin consultas externas),
  sentido (saliente, entrante por dst-nat o IP ruteada) y abonado (percentiles para fijar límites).
- Python 3.10+ solo con la biblioteca estándar. Funciona con RouterOS 6.49 y 7.x.

El agente de Claude Code `trafico-mikrotik` (`.claude/agents/trafico-mikrotik.md`) usa este CLI, interpreta el
perfil y propone la capa de firewall de la categoría (`propuestas/`), siempre en fase de detección primero.

## Servidor con panel web

```sh
apt-get install -y git
git clone https://github.com/mtandazo35/mikrotik-traffic-profiler /opt/mikrotik-traffic-profiler
bash /opt/mikrotik-traffic-profiler/deploy/install.sh            # --puerto 8080 por defecto
```

Deja: usuario de servicio `mtp`; llave RSA 4096 para los routers (RouterOS 6 no acepta ed25519) en
`/var/lib/mikrotik-traffic-profiler/.ssh/`; configuración en `/etc/mikrotik-traffic-profiler/` (inventario,
`mtp.env`, `web.json` con la clave del panel en PBKDF2); datos en `/var/lib/mikrotik-traffic-profiler/data/`.
Servicios: `mtp-web` (panel), `mtp-analizar.timer` (23:30) y, por router, `mtp-recolectar@<router>.timer`
(09:00, 15:00, 20:30 y 21:30 hora de Ecuador; 4 muestras cada 15 min). La clave del panel se muestra una sola vez;
se cambia con `python3 -m mtp.web --config /etc/mikrotik-traffic-profiler/web.json --cambiar-clave` (lee de stdin).

El panel muestra routers, muestras, descubrimientos, informes, tareas y timers, lanza las mismas acciones de solo
lectura que el CLI y trae su apartado de Documentación. Actualizar:
`git -C /opt/mikrotik-traffic-profiler pull && systemctl restart mtp-web`.

## Uso del CLI

```sh
cp inventario.example.json inventario.json   # completar routers, acceso y CIDR por categoría
python trafico.py descubrir  --router core-a                 # pools, NAT, filtros, conntrack (solo print)
python trafico.py contar     --router core-a --categoria residencial
python trafico.py recolectar --router core-a --categoria residencial --repetir 4 --intervalo 15
python trafico.py asn                                       # baja/refresca la tabla IP→ASN (>7 días)
python trafico.py analizar   --categoria residencial --ip2asn data/ip2asn-v4.tsv.gz
```

Acceso: `transporte: "ssh"` usa OpenSSH con llave (`BatchMode`); `transporte: "plink"` usa PuTTY con la clave
en la variable de entorno que nombre `password_env`. La clave nunca va en el inventario. Lo ideal es un usuario
del grupo `read` limitado por `address=` a la IP desde donde se recolecta.

Todo lo que sale de los routers queda en `data/` (ignorado por git): `crudo/<router>/<categoria>/` con un
`muestras.jsonl` por carpeta, `descubrimiento/` e `informes/`.

## Límites conocidos

- Cada muestra es una foto de las conexiones vivas: lo muy corto (DNS, NTP) sale subrepresentado. Muestrear en
  varias franjas y días.
- Con FastTrack por hardware los bytes de conntrack no avanzan: el informe ordena por abonados y conexiones.
- Solo IPv4 (`/ip firewall connection`). IPv6 queda para una segunda fase.
- Para vigilancia continua y validar la política ya aplicada, la fase 2 es IPFIX a un colector
  (ver `mikrotik-flowguard-installer`).

## Pruebas

```sh
python -m unittest discover -s tests -t . -v
```
