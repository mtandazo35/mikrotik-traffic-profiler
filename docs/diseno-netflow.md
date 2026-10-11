# Diseño: analizador NetFlow permanente por categoría de abonado

Especificación para implementar en paralelo (constructor A: ingesta y datos; constructor B: presentación y
firewall). Es lo único que hay que leer además del código. Las direcciones de los ejemplos son de documentación
(192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 100.64.0.0/10). Nada de IPs ni nombres reales en el repositorio.

Objetivo: registrar **todas** las conexiones de los abonados (no fotos) a partir de NetFlow v9 de los cores
MikroTik, guardarlas agregadas por router, categoría, sentido, servicio, destino (ASN) y abonado, y con eso
clasificar cada protocolo/puerto de una categoría (esencial, usado, minoritario, riesgo, no observado) y generar
una propuesta de firewall en modo detección. La recolección por conntrack (fotos) sigue igual y complementa: da
**concurrencia** (para `connection-limit`); NetFlow da **tasa y cobertura completa** (para `dst-limit`, % de
abonados, destinos, consumo).

---

## 0. Qué dice la documentación (y qué no)

### RouterOS Traffic Flow

| Tema | Hallazgo | Fuente |
|---|---|---|
| Propiedades | `interfaces` (defecto `all`), `cache-entries` (defecto **4k**), `active-flow-timeout` (defecto 30m), `inactive-flow-timeout` (defecto 15s); en v7 además `packet-sampling`, `sampling-interval`, `sampling-space`. | [T1], [T2] |
| Target | `dst-address`, `port` (defecto 2055), `src-address`, `version` (1, 5, 9, IPFIX), `v9-template-refresh` (defecto 20 paquetes), `v9-template-timeout` (defecto vacío). La documentación vieja (RouterOS 3) usaba `address=IP:puerto`; 6.49 y 7.x usan `dst-address` + `port`. La wiki de v6 ya no está en línea (redirige a help.mikrotik.com): **confirmar en el canario con `/ip traffic-flow target add ?`**. | [T1], [T5] |
| Dónde se cuenta | "al final de las cadenas input, forward y output": solo lo que llega a esas cadenas. Como el src-nat ocurre después (postrouting) y el des-NAT de las respuestas antes (prerouting), **el abonado aparece con su IP privada en ambos sentidos**. Con CGNAT en el core, esto es justo lo que necesitamos. | [T1] |
| NAT en IPFIX (v7) | Campos opcionales `nat-src-address`, `nat-dst-address`, `nat-src-port`, `nat-dst-port`, `nat-events`. **No los necesitamos** (la IP privada ya viene en `src-address`); por eso v9 alcanza. | [T1] |
| Sentido respecto a `interfaces=` | La documentación **no dice** si se exporta lo que entra, lo que sale o ambos. Hay reportes no oficiales de que solo se ve lo que **entra** por las interfaces listadas [T6] [T8]. Si es así, exportando solo la interfaz de clientes se ve la **subida** (y por tanto todas las conexiones que abre el abonado y las respuestas que da), pero **no la bajada**. Se diseña para funcionar en ambos casos y se **mide en el canario** (sección 6.3). | [T1], [T6], [T8] |
| hw-offload | "HW offloaded traffic will not be seen in Traffic Flow flows". Incluye L3 HW offload de switches/CCR y bridge con `hw=yes`. | [T1] |
| FastTrack | **Contradicción**: la página actual "Packet Flow" lista `ip traffic-flow` entre lo que FastTrack se salta [T3]; la wiki v6 lo marcaba "(restriction removed in 6.33)" y el changelog de 6.33 dice que se añadió traffic-flow a las fastpath [T4]. **Se mide en el canario** (sección 6.3). | [T3], [T4] |
| `cache-entries` | 4k por defecto es poco para un core con miles de abonados (la tabla se llena y los flujos salen antes de tiempo, más registros). Guías de terceros usan 128k. | [T1], [T7] |
| `src-address` | Conviene fijarlo: el colector identifica al router por la IP de origen del paquete UDP. Si el envío pasa por src-nat o VPN, llega con otra IP. | [T1], [T7] |

### nfdump en Debian 13

Versión: **`nfdump 1.7.5-2+deb13u1`** (trixie/main; `apt-cache policy nfdump` en el servidor, no instalado aún).
Trae `nfcapd`, `nfdump`, `nfexpire`. Lo verificado en el código fuente y las páginas de manual de esa versión exacta [N1]:

- **El paquete arranca su propio nfcapd como root en UDP 2055.** `debian/default.conf` se instala como
  `/etc/nfdump/default.conf` con `options='-l /var/cache/nfdump -p 2055'` y el generador
  `/usr/lib/systemd/system-generators/nfdump-generator` crea `nfdump@default.service` para cada
  `/etc/nfdump/*.conf` con `options` no vacío. Ese proceso no tiene retención y choca con nuestro puerto 2055.
  `install.sh` debe neutralizarlo (sección 4.4).
- `nfcapd`: el directorio es `-w` (`-l` es legado y avisa). Puerto por defecto 9995. `-M dir` = exportadores
  dinámicos: un subdirectorio por IP de exportador con `.` y `:` cambiados por `-` (`192.0.2.1` → `192-0-2-1`).
  `-t seg` rotación (defecto 300, mínimo 2). `-B bytes` buffer del socket. `-4` solo IPv4. `-C none` no lee
  configuración. `-e` auto-expira (no lo usamos). `-n ident,IP,dir` fija exportadores (no lo usamos).
- **Rareza de 1.7.5**: `-t` fija la compresión en LZ4 por su cuenta, y `-z` después de `-t` aborta con
  "Use one compression". No pasar `-z`.
- Archivo en curso: `<dir>/nfcapd.current.<pid>`. Al rotar se **renombra** a `nfcapd.AAAAmmddHHMM` (hora
  **local** del proceso, por eso el colector corre con `TZ=UTC`); con `-t` < 60 el nombre lleva segundos. El
  nombre es el **inicio** del intervalo. Si el destino ya existe (reinicio dentro del mismo intervalo), nfcapd
  **añade** al archivo existente (`RenameAppend`): un archivo cerrado puede crecer una vez más, por eso el
  procesador espera dos intervalos (sección 4.2). Cada directorio tiene además un `.nfstat` (contabilidad).
- `nfdump -o "csv:%tok,%tok,..."`: CSV con las columnas pedidas, separadas por coma, sin relleno. **Siempre
  imprime una línea de cabecera** (también con `-q`). `%pr` sale **numérico** (6, 17, 1…), bytes y paquetes
  como enteros planos, `%flg` como 8 caracteres `CEUAPRSF` con `.` en los ausentes (p. ej. `...A..S.`), `%dp`
  de ICMP como `tipo.código` (`8.0`). `%ra` = IP del exportador (no hace falta: la da el directorio).
- `nfdump -I -r archivo`: estadística del archivo sin leer los registros, líneas `Clave: valor`
  (`Flows:`, `Packets:`, `Bytes:`, `First:`, `Last:`, `Sequence failures:`).

---

## 1. Decisiones de arquitectura

| # | Decisión | Por qué |
|---|---|---|
| D1 | **Colector `nfcapd` de Debian**, un solo proceso, usuario `mtp`, **UDP 2055**, `-M` (exportadores dinámicos), `-t 60`, sin `-z`. | Paquete oficial, C, estable, poca RAM. 2055 lo acordó el operador; > 1024, no necesita root. `-M` permite dar de alta routers sin reiniciar el colector. |
| D2 | **NetFlow v9** en todos los routers (6.49 y 7.x). | Mismo comando en ambas versiones, plantilla con todo lo que usamos; IPFIX solo añade campos NAT que no hacen falta. |
| D3 | **Rotación de 60 s = ventana de análisis de 1 minuto.** Cada archivo es un minuto de un exportador y se procesa **entero en una transacción**. | Archivos chicos (memoria acotada), latencia baja, idempotencia natural (un archivo = una unidad) y las métricas por abonado salen "por minuto", que es la unidad de `dst-limit`. |
| D4 | **Exportador → router**: el nombre del subdirectorio (`192-0-2-1`) da la IP; se busca en el inventario el router cuyo `exportador` es esa IP, o, si no tiene `exportador`, cuyo `host` es esa IP. Sin coincidencia = **exportador desconocido**: no se procesa, se registra (IP, primera/última vez, archivos, flujos) y el panel lo muestra con el aviso "anotar esta IP en Routers → IP desde la que exporta". | El caso típico de error es el envío que sale por NAT/VPN con otra IP: así se ve en vez de perderse en silencio. |
| D5 | **Flujo → abonado/categoría**: un lado del flujo es abonado si su IP cae en un CIDR de una categoría **de ese router**. Si cae el origen: lado `src` (bytes de **subida**); si cae el destino: lado `dst` (bytes de **bajada**). Si caen los dos en la misma categoría: sentido `interna`. Si caen en categorías distintas: una observación por cada categoría. | Con CGNAT el abonado solo se distingue por la IP privada, que es la que exporta Traffic Flow. |
| D6 | **Flujos que no son de ninguna categoría**: no se leen. El filtro de `nfdump` (`net A or net B …` con los CIDR del router) los descarta en C. Solo se cuentan: `Flows:` de `nfdump -I` menos los leídos = **% fuera de categoría** por exportador. Si pasa de 30 % el panel avisa: "¿la WAN está en `interfaces=`? ¿faltan rangos en el inventario?". | Volumen: lo que no es de abonados no se procesa ni se guarda. Y es la alarma temprana del error que ya tumbó un servidor (meter la WAN multiplicó ×17 el volumen). |
| D7 | **Sentido y puerto de servicio** por reglas deterministas (sección 1.1), porque NetFlow es unidireccional y no trae estado de conexión. | Reproduce `saliente`/`entrante` de `conntrack.clasificar` para que informes y firewall hablen igual. |
| D8 | **Streaming**: `nfdump` en `subprocess.Popen`, lectura línea a línea, agregación en diccionarios **de un archivo** (un minuto), escritura y descarte. Nunca se carga un archivo ni un día en memoria. Tope duro `MemoryMax=750M` en la unidad. | La lección del OOM: un proceso que cargaba archivos nfcapd enteros tumbó otro servidor. |
| D9 | **SQLite** (`sqlite3` de la stdlib) en `data/flujos.db`, WAL. Tres niveles: (a) **presencia** abonado×clave por día, retención corta (8–14 d), solo para contar abonados distintos exactos; (b) **agregados diarios** compactos con retención larga (90–400 d); (c) **histogramas** por métrica para percentiles. Crudo nfcapd: **horas** (6 h o 6 GB, lo que llegue antes). | Disco de 20 GB: el crudo se va rápido y lo que queda es chico. Los abonados distintos no son sumables entre archivos; la presencia lo resuelve sin guardar flujos. |
| D10 | **Puertos**: los conteos por día guardan el puerto **exacto**; la presencia por abonado guarda la **clave de servicio** (puerto < 1024 o del catálogo exacto, rango con nombre, o los cubos `-1` = 1024–49151 sin catálogo y `-2` = ≥ 49152). | Los puertos altos aleatorios (P2P, juegos) multiplicarían las filas por abonado sin aportar a la decisión de firewall; los riesgosos están en el catálogo. |
| D11 | **Guardián de disco** dentro del procesador (corre cada minuto): borra crudo ya procesado por edad/tamaño, y en emergencia crudo sin procesar (registrado como `descartado`). | El colector no tiene límite propio y no puede parar solo. |
| D12 | **El sistema no toca los routers.** Solo genera comandos para que los pegue el operador (tarjeta "Exportar NetFlow"). El firewall sale como `.rsc` descargable, en modo detección. | Regla del proyecto: cambios en equipo ajeno solo por el operador. |

### 1.1 Reglas de clasificación de un flujo (las implementa A en `mtp/flujos.py`)

Notación: `ap` = puerto del lado abonado, `rp` = puerto del lado remoto. `es_servicio(proto, p)` =
`p < 1024` o `(proto, p)` en el catálogo exacto de `servicios.py` o dentro de un rango con nombre de
`servicios.py`.

TCP y UDP:

1. `es_servicio(rp)` y no `es_servicio(ap)` → **saliente**, puerto de servicio `rp`.
2. `es_servicio(ap)` y no `es_servicio(rp)` → **entrante**, puerto de servicio `ap`.
3. Los dos o ninguno: el **menor** gana; `rp <= ap` → saliente con `rp`; si no, entrante con `ap`.

ICMP (`%dp` = `tipo.código`): tipos de petición {8, 13, 15, 17}: saliente si el abonado es `src`, entrante si es
`dst`. Resto de tipos (respuestas, errores): saliente si el abonado es `dst`, entrante si es `src`. Puerto de
servicio 0. Otros protocolos (GRE, ESP, AH…): siempre saliente, puerto 0.

Interna: los dos lados en la misma categoría → una sola observación `interna` con abonado = origen.

**Registro de petición** = el que va del lado cliente al lado servidor: `saliente` con abonado `src`, o
`entrante` con abonado `dst`. Las métricas por abonado (sección 3.3) usan solo registros de petición
`saliente` con abonado `src`. Los bytes usan todos los registros.

Proto como texto, igual que `conntrack._PROTO_NUM`: 1 `icmp`, 6 `tcp`, 17 `udp`, 47 `gre`, 50 `ipsec-esp`,
51 `ipsec-ah`; otro → el número como texto.

---

## 2. Comandos RouterOS que genera el panel

La tarjeta **"Exportar NetFlow"** ya existe en `mtp/web.py` (`comandos_netflow(ip, puerto=2055)` → `(buscar,
activar, verificar, quitar)`). B la **extiende** (no la reescribe) con lo siguiente. La IP del colector es la
que ya calcula el panel (`CFG["ip_origen"]`); aquí se escribe `IP_COLECTOR`.

### 2.1 Activar (RouterOS 6.49 y 7.x, misma sintaxis)

```
# 0) Mirar si ya exporta a otro colector (otro sistema del ISP):
/ip traffic-flow print
/ip traffic-flow target print
#    Si ya dice enabled: yes con interfaces puestas: NO ejecutar el "set" de abajo
#    (interfaces es global y cambiaría lo que recibe el otro colector). Solo añadir el target.

# 1) INTERFAZ-CLIENTES = interfaz donde están los gateways de los abonados.
#    Si la VLAN de clientes va montada sobre un bridge, poner el BRIDGE, no la VLAN.
#    Varias: separadas por coma. Si un nombre tiene espacios, todo entre comillas: interfaces="br clientes,vlan20"
#    NUNCA la WAN ni enlaces de tránsito.
/ip traffic-flow set enabled=yes interfaces=INTERFAZ-CLIENTES cache-entries=128k active-flow-timeout=1m inactive-flow-timeout=15s

# 2) Destino. src-address = IP del router con la que este servidor lo ve (la del inventario).
/ip traffic-flow target add dst-address=IP_COLECTOR port=2055 version=9 src-address=IP_DEL_ROUTER v9-template-refresh=20 v9-template-timeout=1m
```

Por qué cada valor:
- `active-flow-timeout=1m`: una conexión larga se reporta cada minuto (los bytes caen en su minuto real; con 30m
  por defecto, una descarga larga aparecería entera al final). `inactive-flow-timeout=15s` es el defecto.
- `cache-entries=128k`: el defecto 4k se llena en un core y fragmenta flujos. En equipos chicos, 64k o 32k.
  Comprobar en el canario que el cambio se aplica sin reinicio (`/ip traffic-flow print`).
- `src-address`: el colector reconoce al router por esa IP. Si se deja vacío y el envío sale por NAT o VPN,
  llega con otra IP y el panel lo marca como exportador desconocido.
- `v9-template-timeout=1m`: con poco tráfico, 20 paquetes pueden tardar minutos; sin plantilla el colector no
  puede decodificar nada (pasa al arrancar o reiniciar el colector).

### 2.2 Verificar en el router

```
/ip traffic-flow print
/ip traffic-flow target print detail
/interface print stats where name=INTERFAZ-CLIENTES
/ip firewall nat print where chain=srcnat
/ip firewall filter print where action=fasttrack-connection
/interface ethernet switch print
```
Qué mirar: `enabled: yes`, la interfaz correcta, el target hacia `IP_COLECTOR:2055` versión 9; que ninguna
regla srcnat cambie el origen del envío hacia `IP_COLECTOR` (si la hay, el operador decide una excepción
`chain=srcnat dst-address=IP_COLECTOR action=accept` arriba de todo); si hay FastTrack con `hw-offload=yes` o
el switch tiene `l3-hw-offloading: yes` (v7), el tráfico acelerado por hardware **no se exporta**. En el panel
(Tráfico → Salud) el exportador debe aparecer con archivos del último minuto.

### 2.3 Quitar (sin romper otro colector)

```
/ip traffic-flow target remove [find dst-address=IP_COLECTOR]
:if ([:len [/ip traffic-flow target find]] = 0) do={ /ip traffic-flow set enabled=no }
```
(La versión actual hace `set enabled=no` sin condición: apaga también el envío a cualquier otro colector.)

---

## 3. Modelo de datos

Archivo: `/var/lib/mikrotik-traffic-profiler/data/flujos.db`. Convenciones:
- `ventana`, `hora`: epoch UTC (inicio del minuto / de la hora). `dia`: entero `AAAAMMDD` en hora de Ecuador,
  calculado con desplazamiento **fijo UTC−5** (`timezone(timedelta(hours=-5))`; Ecuador no tiene horario de
  verano y así no se depende de tzdata en Windows).
- `abonado`, `servidor`, `red`: IPv4 como entero. `sentido`: 0 saliente, 1 entrante, 2 interna. `proto`: número.
- `router`: nombre del inventario. En las tablas `*_7d`, `router='*'` = todos los routers juntos.
- **Abonados de varios routers se cuentan por el par (router, abonado)**: los rangos privados se repiten entre
  cores, la misma IP en dos routers son dos abonados.

### 3.1 DDL (lo crea `flujos_db.crear_esquema`, idempotente)

```sql
PRAGMA auto_vacuum = INCREMENTAL;   -- solo surte efecto si se ejecuta antes de crear la primera tabla
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;

CREATE TABLE IF NOT EXISTS meta (clave TEXT PRIMARY KEY, valor TEXT NOT NULL);
-- claves: version_esquema ('1'), ultima_ejecucion, ultima_retencion, asn_mtime, disco_critico ('0'/'1')

CREATE TABLE IF NOT EXISTS archivos (            -- checkpoint + salud por exportador y minuto
  ruta TEXT PRIMARY KEY,                         -- relativa a data/nfcapd: '192-0-2-1/nfcapd.202610102035'
  exportador TEXT NOT NULL,                      -- '192.0.2.1'
  router TEXT,                                   -- NULL = exportador desconocido
  ventana INTEGER NOT NULL,
  tam INTEGER NOT NULL, mtime INTEGER NOT NULL,
  estado TEXT NOT NULL CHECK (estado IN ('ok','vacio','reintentar','error','desconocido','descartado')),
  intentos INTEGER NOT NULL DEFAULT 0,
  flujos_total INTEGER, bytes_total INTEGER, secuencia_perdida INTEGER,   -- de nfdump -I
  flujos_categoria INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,   -- de lo leído
  omitidos INTEGER,                              -- líneas mal formadas o IPv6
  segundos REAL, procesado INTEGER, borrado INTEGER, error TEXT
);
CREATE INDEX IF NOT EXISTS archivos_ventana ON archivos(ventana);
CREATE INDEX IF NOT EXISTS archivos_router ON archivos(router, ventana);

CREATE TABLE IF NOT EXISTS exportador_desconocido (
  ip TEXT PRIMARY KEY, primero INTEGER, ultimo INTEGER, archivos INTEGER, flujos INTEGER);

CREATE TABLE IF NOT EXISTS asn (asn INTEGER PRIMARY KEY, nombre TEXT NOT NULL, pais TEXT NOT NULL);
-- 0 = sin ASN / no público; -1 = "otros (agrupados)"

CREATE TABLE IF NOT EXISTS dia_cierre (dia INTEGER PRIMARY KEY, cerrado INTEGER, sucio INTEGER NOT NULL DEFAULT 0);

CREATE TABLE IF NOT EXISTS total_hora (
  hora INTEGER, router TEXT, categoria TEXT,
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  abonados_max_ventana INTEGER, ventanas INTEGER,
  PRIMARY KEY (hora, router, categoria)) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS interfaz_dia (       -- qué ifIndex traen tráfico de abonados (diagnóstico)
  dia INTEGER, router TEXT, entrada INTEGER, salida INTEGER, flujos INTEGER, bytes INTEGER,
  PRIMARY KEY (dia, router, entrada, salida)) WITHOUT ROWID;

-- Presencia (abonados distintos exactos). Retención corta.
CREATE TABLE IF NOT EXISTS uso_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER, abonado INTEGER,
  flujos INTEGER, bytes INTEGER,
  PRIMARY KEY (dia, router, categoria, sentido, proto, puerto, abonado)) WITHOUT ROWID;   -- puerto = clave
CREATE TABLE IF NOT EXISTS destino_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, asn INTEGER, abonado INTEGER,
  flujos INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  PRIMARY KEY (dia, router, categoria, asn, abonado)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dns_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, proto INTEGER, puerto INTEGER, servidor INTEGER, abonado INTEGER,
  flujos INTEGER,
  PRIMARY KEY (dia, router, categoria, proto, puerto, servidor, abonado)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS no_publico_abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, red INTEGER, abonado INTEGER, flujos INTEGER, bytes INTEGER,
  PRIMARY KEY (dia, router, categoria, red, abonado)) WITHOUT ROWID;                       -- red = /24

-- Agregados diarios. Contadores se suman por archivo; "abonados" se rellena al cerrar el día (NULL antes).
CREATE TABLE IF NOT EXISTS servicio_dia (
  dia INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER,  -- puerto = clave
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  abonados_max_ventana INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, sentido, proto, puerto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS puerto_dia (
  dia INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER,  -- puerto exacto
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER, abonados_max_ventana INTEGER,
  PRIMARY KEY (dia, router, categoria, sentido, proto, puerto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS destino_dia (
  dia INTEGER, router TEXT, categoria TEXT, asn INTEGER,
  flujos INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, asn)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS dns_dia (
  dia INTEGER, router TEXT, categoria TEXT, proto INTEGER, puerto INTEGER, servidor INTEGER,
  flujos INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, proto, puerto, servidor)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS no_publico_dia (
  dia INTEGER, router TEXT, categoria TEXT, red INTEGER, flujos INTEGER, bytes INTEGER, abonados INTEGER,
  PRIMARY KEY (dia, router, categoria, red)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS abonado_dia (
  dia INTEGER, router TEXT, categoria TEXT, abonado INTEGER,
  flujos INTEGER, paquetes INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER, ventanas INTEGER,
  max_flujos INTEGER, max_tcp_nuevas INTEGER, max_udp INTEGER, max_ips INTEGER, max_puertos INTEGER,
  max_peers_udp INTEGER, max_syn INTEGER,
  PRIMARY KEY (dia, router, categoria, abonado)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS hist_dia (            -- una observación = un abonado activo en un minuto
  dia INTEGER, router TEXT, categoria TEXT, metrica TEXT, cubo INTEGER, n INTEGER,
  PRIMARY KEY (dia, router, categoria, metrica, cubo)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS senal_dia (
  dia INTEGER, router TEXT, categoria TEXT,
  tipo TEXT CHECK (tipo IN ('sensible','reflector','barrido','p2p')),
  detalle TEXT,                                  -- 'tcp/25', 'udp/1900', 'tcp/23', '' (p2p)
  abonado INTEGER, flujos INTEGER, remotos_max_ventana INTEGER, ventanas INTEGER, ultima INTEGER,
  PRIMARY KEY (dia, router, categoria, tipo, detalle, abonado)) WITHOUT ROWID;

-- Fotos de 7 días (exactas), calculadas al cerrar cada día; 'hasta' = último día incluido.
CREATE TABLE IF NOT EXISTS servicio_7d (
  hasta INTEGER, router TEXT, categoria TEXT, sentido INTEGER, proto INTEGER, puerto INTEGER,
  abonados INTEGER, flujos INTEGER, bytes INTEGER, dias_observado INTEGER,
  PRIMARY KEY (hasta, router, categoria, sentido, proto, puerto)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS destino_7d (          -- top 500 ASN por (router, categoria)
  hasta INTEGER, router TEXT, categoria TEXT, asn INTEGER,
  abonados INTEGER, flujos INTEGER, bytes_subida INTEGER, bytes_bajada INTEGER,
  PRIMARY KEY (hasta, router, categoria, asn)) WITHOUT ROWID;
CREATE TABLE IF NOT EXISTS activos_7d (
  hasta INTEGER, router TEXT, categoria TEXT, abonados INTEGER, dias_con_datos INTEGER,
  PRIMARY KEY (hasta, router, categoria)) WITHOUT ROWID;
```

Escritura: `INSERT … ON CONFLICT(pk) DO UPDATE SET flujos = flujos + excluded.flujos, …,
abonados_max_ventana = MAX(abonados_max_ventana, excluded.abonados_max_ventana)` con `executemany`, todo un
archivo en **una** transacción que también inserta su fila en `archivos`. Si algo falla, `ROLLBACK`: ni
contadores ni checkpoint. Así reprocesar es imposible y perder un archivo a medias también.

### 3.2 Granularidad y por qué

| Nivel | Granularidad | Para qué |
|---|---|---|
| Ventana | 1 minuto (un archivo) | Métricas por abonado (percentiles), barridos, P2P. Vive solo en memoria mientras se procesa. |
| Hora | `total_hora` | Gráfico "por hora". |
| Día | `*_dia` | Tops por periodo, consumo por abonado, señales. |
| 7 días | `*_7d` | % de abonados exacto para la clasificación del firewall (ventana mínima de diseño). |

### 3.3 Métricas por abonado y minuto (`hist_dia.metrica`, `abonado_dia.max_*`)

Sobre registros de petición `saliente` con abonado `src`, en un minuto:

| métrica | definición |
|---|---|
| `flujos` | 5-tuplas distintas (`proto, sport, dst, dport`) |
| `tcp_nuevas` | registros TCP con `S` en flags (intentos de conexión; base de `dst-limit`) |
| `udp` | 5-tuplas UDP distintas |
| `ips` | IP remotas distintas |
| `puertos` | pares (proto, `rp`) distintos |
| `peers_udp` | IP remotas UDP con `rp >= 1024` y `rp` fuera de `analizar._UDP_NO_P2P` |
| `syn` | registros TCP con `S` y sin `A` (no contestados) |

Cada abonado activo en el minuto aporta una observación por métrica (también los ceros) a `hist_dia`.
**Cubos**: `cubo(v) = v` si `v < 100`; si no, dos cifras significativas truncadas (`1234 → 1200`).
Percentil p: menor cubo con acumulado ≥ `ceil(p/100 · N)`; se informa su **cota superior**
(`cubo` si < 100; si no `cubo + 10**(dígitos−2) − 1`). Error ≤ 10 %, siempre hacia arriba (conservador para
límites). `max` sale exacto de `abonado_dia.max_*`.

Señales por minuto (constantes importadas de `mtp/analizar.py`, sin modificarlo):
- `sensible`: petición saliente a `(proto, rp)` en `_SENSIBLES_SALIENTES`.
- `reflector`: sentido entrante, UDP, puerto de servicio en `_REFLECTORES`.
- `barrido`: ≥ `_UMBRAL_BARRIDO` (50) IP remotas distintas al mismo `(proto, rp)` en un minuto, excepto
  tcp/80, tcp/443, udp/443.
- `p2p`: `peers_udp` ≥ `_UMBRAL_P2P` (100) en un minuto.

DNS: petición saliente a `(proto, rp)` en `_PUERTOS_DNS` → `dns_*`. No públicos: remoto con
`not IPv4Address(remoto).is_global` y sentido ≠ interna → `no_publico_*` (red /24).

### 3.4 Cierre del día y poda (A)

Un día D (local) se **cierra** cuando `ahora ≥ fin de D + 2 h` y no está cerrado, o está `sucio` (llegó un
archivo de D después del cierre). Cerrar D:
1. `servicio_dia.abonados`, `destino_dia.abonados`, `dns_dia.abonados`, `no_publico_dia.abonados` =
   `COUNT(*)` de la presencia de D agrupada por su clave.
2. Poda de `puerto_dia`: filas con puerto ≥ 1024 que no son del catálogo, `abonados_max_ventana < 2` y
   `flujos < 100` se suman en la fila del cubo (-1 si < 49152, -2 si no) y se borran.
3. Poda de `destino_dia`: ASN con `abonados < 2` y `bytes_subida+bytes_bajada < 50 MB` → `asn = -1`.
4. Fotos `servicio_7d`, `destino_7d`, `activos_7d` con `hasta = D` (días D−6..D), por router y `'*'`.
5. `dia_cierre(D) = (ahora, sucio=0)`.

Se puede repetir sin efectos secundarios mientras la presencia de D siga guardada.

### 3.5 Consultas

- **% de abonados que usan el puerto X** (7 días):
  `servicio_7d.abonados / activos_7d.abonados × 100` para `hasta = ayer`. Para "hoy": `COUNT(*)` de
  `uso_abonado_dia` del día / `COUNT(*)` de `abonado_dia` del día. Para 30 días: máximo diario
  (`abonados_modo = "max_diario"`).
- **Top destinos por bytes**: `SUM(bytes_subida + bytes_bajada)` de `destino_dia` agrupado por `asn`, unido a
  `asn`. **Por abonados**: `destino_7d.abonados` (7 d) o presencia (hoy).
- **Top consumidores**: `SUM(bytes_bajada)` (o subida) de `abonado_dia` agrupado por `(router, abonado)`.
- **Percentiles por abonado y minuto**: suma de `hist_dia.n` por `(metrica, cubo)` en el periodo y cálculo de
  3.3; `max` = `MAX(max_*)` de `abonado_dia`.
- **Señales**: `senal_dia` agrupado por `(tipo, detalle, router, abonado)`.

### 3.6 Retención y presupuesto de disco

| Tabla | Retención | Peor caso/día (5 routers × 5000 abonados = 25 000) | Total |
|---|---:|---:|---:|
| crudo nfcapd | 6 h o 6 GB | 10–20 MB/min/router → 3–6 GB/h con 5 routers | ≤ 6 GB |
| `uso_abonado_dia` | 14 d | 25 000 × ~40 claves × ~45 B ≈ 45 MB | 630 MB |
| `destino_abonado_dia` | 8 d | 25 000 × ~60 ASN × ~45 B ≈ 68 MB | 540 MB |
| `dns_/no_publico_abonado_dia` | 14 d | ≈ 3 MB | 42 MB |
| `abonado_dia` | 90 d | 25 000 × ~110 B ≈ 2,8 MB | 250 MB |
| `puerto_dia` (tras poda) | 90 d | ≈ 0,5 MB (+50 MB transitorios el día en curso) | 95 MB |
| `servicio_dia` | 400 d | 10 router·cat × 2 sentidos × 300 claves × 60 B ≈ 0,36 MB | 145 MB |
| `destino_dia` (tras poda) | 180 d | 10 × 1500 × 60 B ≈ 0,9 MB | 160 MB |
| `hist_dia` | 400 d | 10 × 7 métricas × 150 cubos × 35 B ≈ 0,37 MB | 150 MB |
| `servicio_7d`/`destino_7d` | 90 d | ≈ 0,6 MB | 55 MB |
| `total_hora`, `interfaz_dia`, `senal_dia`, `dns_dia`, `no_publico_dia`, `activos_7d` | 90–400 d | < 0,2 MB | < 60 MB |
| `archivos` | 35 d | 5 × 1440 × 200 B ≈ 1,4 MB | 50 MB |

Peor caso total ≈ 2,2 GB de base (≈ 3 GB con índices y WAL) + 6 GB de crudo = **9 GB de 18 GB libres**.
Caso típico (1 router, 5000 abonados): ≈ 0,5 GB de base. Retención: borrado diario por `dia`/`ventana` y
`PRAGMA incremental_vacuum(5000)`; al final de cada ejecución `PRAGMA wal_checkpoint(TRUNCATE)`.

### 3.7 Presupuesto de RAM (1,9 GiB, sin swap)

| Proceso | Estimación | Tope |
|---|---|---|
| `nfcapd` | 20–60 MB (buffer 8 MB) | `MemoryMax=256M` |
| procesador | Python ≈ 30 MB + tabla ASN en `array('I')` ≈ 6 MB + nombres ≈ 30 MB + un minuto de un router: a 20 MB/min ≈ 0,6–1 M registros, ~½ de petición → conjuntos ≈ 150–250 MB + `nfdump` hijo ≈ 30 MB + caché SQLite 64 MB | `MemoryHigh=600M`, `MemoryMax=750M` |
| web | ≈ 50 MB | — |

Total < 1,1 GB. Si un minuto supera **2 000 000** de claves distintas en memoria, el procesador aborta ese
archivo (`estado='error'`, `error='demasiado grande: revisar interfaces= del router'`) en vez de crecer.
CPU: Python ≈ 150 k registros/s por núcleo → un router a 20 MB/min ≈ 10 % de un núcleo; cinco ≈ 50 %.

---

## 4. Proceso

### 4.1 Colector: `deploy/systemd/mtp-colector.service` (A)

```ini
[Unit]
Description=Colector NetFlow v9 (nfcapd) del perfilador de trafico
After=network-online.target
Wants=network-online.target

[Service]
User=mtp
Group=mtp
UMask=0027
Environment=TZ=UTC
EnvironmentFile=/etc/mikrotik-traffic-profiler/mtp.env
ExecStart=/usr/bin/nfcapd -C none -4 -M /var/lib/mikrotik-traffic-profiler/data/nfcapd -p ${PUERTO_NETFLOW} -t ${ROTACION_NETFLOW} -B 8388608
Restart=always
RestartSec=5
MemoryMax=256M
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictNamespaces=yes
LockPersonality=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ReadWritePaths=/var/lib/mikrotik-traffic-profiler/data/nfcapd

[Install]
WantedBy=multi-user.target
```
`-B 8388608` solo surte efecto si `net.core.rmem_max` lo permite (sin root el kernel lo recorta): lo fija
`install.sh`. Al pararse (SIGTERM) nfcapd cierra y renombra el archivo en curso.

### 4.2 Procesador: `mtp-flujos.service` + `mtp-flujos.timer` (A)

```ini
# mtp-flujos.service
[Unit]
Description=Procesa los archivos NetFlow cerrados y agrega por categoria (streaming)
After=network-online.target

[Service]
Type=oneshot
User=mtp
Group=mtp
WorkingDirectory=/opt/mikrotik-traffic-profiler
Environment=TZ=America/Guayaquil PYTHONDONTWRITEBYTECODE=1
EnvironmentFile=/etc/mikrotik-traffic-profiler/mtp.env
ExecStartPre=-/usr/bin/python3 trafico.py --datos /var/lib/mikrotik-traffic-profiler/data asn
ExecStart=/usr/bin/python3 trafico.py --inventario /var/lib/mikrotik-traffic-profiler/inventario.json --datos /var/lib/mikrotik-traffic-profiler/data flujos-procesar --max-segundos 600
TimeoutStartSec=30min
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
MemoryHigh=600M
MemoryMax=750M
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
ReadWritePaths=/var/lib/mikrotik-traffic-profiler

# mtp-flujos.timer
[Unit]
Description=Procesar NetFlow cada minuto

[Timer]
OnBootSec=2min
OnCalendar=*-*-* *:*:20
AccuracySec=1s

[Install]
WantedBy=timers.target
```
(`trafico.py asn` no descarga si la tabla tiene menos de 7 días: es casi gratis cada minuto. Hace falta aquí
porque `mtp-analizar` solo corre si hay muestras de conntrack.)

Una ejecución de `flujos-procesar`:
1. Candado `data/flujos.lock` (`fcntl.flock`, no bloqueante; si está tomado, salir 0). En Windows (pruebas) sin
   candado.
2. `crear_esquema`; cargar inventario; tabla ASN si cambió el `mtime` del TSV (`meta.asn_mtime`).
3. **Guardián** (4.3).
4. Listar `data/nfcapd/*/nfcapd.AAAAmmddHHMM` (regex `^nfcapd\.(\d{12})$`; ignorar `nfcapd.current.*`,
   `.nfstat` y lo demás). Directorio → IP (`-` → `.`, validar IPv4). **Listo** si
   `ahora ≥ ventana + 2·ROTACION + 30 s` y `mtime ≤ ahora − 30 s` (cubre el `RenameAppend` tras un reinicio).
   Saltar los que ya están en `archivos` con estado final (`ok`, `vacio`, `error`, `desconocido`,
   `descartado`). Si uno `ok` cambió de `tam`/`mtime`, registrar aviso y **no** reprocesar. Orden: ventana
   ascendente.
5. Por archivo:
   - Exportador sin router → `exportador_desconocido` (upsert) + fila `archivos` `desconocido`.
   - `nfdump -I -r ARCHIVO` → `Flows`, `Bytes`, `Sequence failures`.
   - `nfdump -r ARCHIVO -q -N -o "csv:%pr,%sa,%sp,%da,%dp,%flg,%ipkt,%ibyt,%fl,%in,%out" "net C1 or net C2 …"`
     con los CIDR de todas las categorías del router. `Popen(stdout=PIPE, text=True, encoding="ascii",
     errors="replace", stderr=<TemporaryFile>)`; `for linea in p.stdout`; `p.wait`. Vigilante: matar a los
     600 s.
   - Línea: saltar la cabecera (primer carácter no dígito) y las de 11 campos que no son IPv4
     (`omitidos += 1`). Ejemplo de cabecera y línea reales del formato:
     ```
     proto,srcAddr,srcPort,dstAddr,dstPort,flags,inPackets,inBytes,flows,input,output
     6,100.64.1.10,51514,192.0.2.10,443,...AP.S.,12,4310,1,7,1
     1,100.64.1.15,0,192.0.2.53,8.0,........,1,84,1,7,1
     ```
   - Clasificar (1.1) y agregar en memoria (3.3).
   - Código de salida ≠ 0, excepción o tope de claves → `ROLLBACK`, `intentos += 1`; estado `reintentar` si
     `intentos < 3`, si no `error` con las últimas 400 letras de stderr.
   - Éxito → una transacción: todos los upserts + fila `archivos` `ok` (o `vacio` si 0 líneas).
   - Guardián rápido cada 20 archivos.
   - Parar de tomar archivos nuevos al pasar `--max-segundos`.
6. Cerrar días pendientes (3.4). Retención una vez por día (`meta.ultima_retencion`).
7. `meta.ultima_ejecucion`; `wal_checkpoint(TRUNCATE)`. Salida 0 salvo error fatal (base inaccesible).

Con `--sin-espera` (pruebas) no se aplica la regla de "listo".

### 4.3 Guardián de disco (A, en `mtp/flujos.py`)

Variables de `mtp.env` (por defecto): `CRUDO_HORAS=6`, `CRUDO_MAX_GB=6`, `DISCO_MIN_LIBRE_PCT=15`,
`DISCO_CRITICO_PCT=8`. Orden:
1. Borrar crudo con estado final y `ventana` más vieja que `CRUDO_HORAS`; de exportadores desconocidos, a la hora.
2. Si `data/nfcapd` pesa más de `CRUDO_MAX_GB`: borrar procesados del más viejo al más nuevo hasta el 90 %.
3. Si el libre del sistema de archivos < `DISCO_MIN_LIBRE_PCT`: borrar procesados (aunque sean recientes)
   hasta libre ≥ mínimo + 5.
4. Si aún < `DISCO_CRITICO_PCT`: borrar **sin procesar**, del más viejo, marcándolos `descartado`
   (`error='disco lleno'`), registrar ERROR en el journal y `meta.disco_critico=1`, hasta libre ≥ crítico + 2.
5. Borrar `nfcapd.current.<pid>` cuyo pid no existe y con `mtime` > 10 min (restos de una caída).
6. Marcar `archivos.borrado` en lo borrado.

Devuelve `{"borrados": int, "descartados": int, "libre_pct": float, "crudo_bytes": int, "estado": "ok"|"aviso"|"critico"}`.
La función de uso de disco se inyecta (`uso=shutil.disk_usage`) para poder probar "disco lleno".

### 4.4 Cambios en `deploy/install.sh` (A)

1. `apt-get install -y nfdump` si falta `nfcapd`.
2. **Neutralizar la instancia de Debian**: si `/etc/nfdump/default.conf` tiene `options` no vacío, copiarlo a
   `/etc/nfdump/default.conf.antes-mtp` (una sola vez) y dejar `options=''` con un comentario
   "desactivado por mikrotik-traffic-profiler: usa mtp-colector.service". Luego `systemctl daemon-reload` y
   `systemctl stop 'nfdump@default.service' 2>/dev/null || true`. Comprobar que nada escucha en el puerto
   antes de arrancar el nuestro (`ss -ulnp`), y si lo hay, abortar con mensaje.
3. `install -d -o mtp -g mtp -m 0750 "$VAR/data/nfcapd"`.
4. `/etc/sysctl.d/60-mtp-netflow.conf` con `net.core.rmem_max = 8388608` y `sysctl -p` de ese archivo.
5. Añadir a `mtp.env` las variables que falten (sin pisar): `PUERTO_NETFLOW=2055`, `ROTACION_NETFLOW=60`,
   `CRUDO_HORAS=6`, `CRUDO_MAX_GB=6`, `DISCO_MIN_LIBRE_PCT=15`, `DISCO_CRITICO_PCT=8`.
6. `systemctl enable --now mtp-colector.service mtp-flujos.timer` (las unidades ya se copian con `mtp-*`).
7. Al final, imprimir: "NetFlow: UDP 2055 en esta IP; los routers se configuran con la tarjeta Exportar NetFlow".

---

## 5. Reparto

### 5.1 Archivos (ninguno es de los dos)

| Constructor A (ingesta y datos) | Constructor B (presentación y firewall) |
|---|---|
| `mtp/flujos.py` (nuevo): parseo, clasificación, agregación, ASN, guardián, `procesar` | `mtp/web.py`: páginas Tráfico y Firewall, tarjeta Exportar NetFlow, Documentación |
| `mtp/flujos_db.py` (nuevo): esquema, upserts, cierre, retención, **consultas** | `mtp/firewall.py` (nuevo): clasificación y `.rsc` |
| `mtp/servicios.py`: solo **añadir** funciones (5.2); `nombre()` no cambia | `README.md` |
| `trafico.py`: subcomandos `flujos-*` | `.claude/agents/trafico-mikrotik.md` |
| `deploy/install.sh`, `deploy/systemd/mtp-colector.service`, `mtp-flujos.service`, `mtp-flujos.timer` | `tests/test_web.py`, `tests/test_web_trafico.py` (nuevo), `tests/test_firewall.py` (nuevo) |
| `tests/emisor_netflow.py`, `tests/nfdump_falso.py`, `tests/test_flujos.py`, `tests/test_flujos_db.py`, `tests/test_extremo_netflow.py` (nuevos) | |

Nadie toca: `mtp/analizar.py`, `conntrack.py`, `router.py`, `inventario.py`, `mtp-web.service`,
`mtp-analizar.*`, `mtp-recolectar.*`, `docs/diseno-netflow.md`. Si alguien necesita cambiar uno de ellos, lo
pide al coordinador.

### 5.2 Contrato de `mtp/servicios.py` (A lo añade; B lo puede usar)

```python
PUERTO_ALTO = -1      # 1024–49151 sin catálogo
PUERTO_EFIMERO = -2   # 49152–65535
def proto_nombre(numero: int) -> str            # 6 -> "tcp"; 99 -> "99"
def rango(proto: str, puerto: int) -> tuple[int, int, str] | None   # (desde, hasta, texto) de _RANGOS
def es_servicio(proto: str, puerto: int) -> bool
def clave(proto: str, puerto: int) -> int       # exacto | desde del rango | -1 | -2 ; 0 si no es tcp/udp
def hasta(proto: str, clave: int) -> int        # fin del rango; = clave si exacto; 49151 / 65535 para -1/-2; 0
def etiqueta(proto: str, clave: int) -> str     # "tcp/443", "udp/3478-3481", "tcp/1024-49151", "udp/49152-65535", "icmp"
def nombre_clave(proto: str, clave: int) -> str # nombre(); -1 "otros puertos sin catálogo"; -2 "efímero / dinámico"
```

### 5.3 Contrato de `mtp/flujos_db.py` (A lo implementa; B lo consume)

Reglas comunes:
- `categoria: str` obligatoria; `router: str | None` (None = todos).
- `periodo` ∈ `PERIODOS = ("hoy", "ayer", "7d", "30d")`. "7d" = los 7 días completos que terminan ayer.
  Otro valor → `ValueError`.
- IPs como `str`, bytes y contadores como `int`, porcentajes `float` con 1 decimal, fechas ISO con
  desplazamiento `-05:00`. Todo serializable con `json.dumps`.
- Base vacía o sin datos del filtro: listas vacías, dicts con ceros. Nunca excepción.
- `proto` siempre como texto (`servicios.proto_nombre`), `sentido` como `"saliente" | "entrante" | "interna"`.

```python
RUTA_RELATIVA = "flujos.db"
PERIODOS = ("hoy", "ayer", "7d", "30d")

def abrir(ruta, solo_lectura: bool = False) -> sqlite3.Connection
    # solo_lectura=True: FileNotFoundError si no existe; URI "file:...?mode=ro"; busy_timeout 5000.

def routers_con_datos(con) -> list[str]
def categorias_con_datos(con) -> list[str]

def resumen(con, categoria, router=None, periodo="7d") -> dict
# {"categoria": "residencial", "routers": ["core-a"], "periodo": "7d",
#  "desde": "2026-10-03", "hasta": "2026-10-09", "dias_con_datos": 7,
#  "abonados_activos": 4210, "abonados_modo": "exacto",          # o "max_diario"
#  "flujos": 123456789, "bytes_subida": 1100000000000, "bytes_bajada": 9800000000000,
#  "relacion_bajada_subida": 8.9,                                  # None si subida = 0
#  "ultima_ventana": "2026-10-10T20:35:00-05:00",                 # None si nunca
#  "pendientes": 3}                                                 # archivos listos sin procesar

def por_hora(con, categoria, router=None, periodo="hoy") -> list[dict]
# Serie continua (huecos con ceros). Paso 3600 s; para "30d", 86400 s.
# [{"inicio": "2026-10-10T20:00:00-05:00", "paso_segundos": 3600, "flujos": 51234,
#   "bytes_subida": 1200000000, "bytes_bajada": 9900000000, "abonados_max_ventana": 1830}, ...]

def top_destinos(con, categoria, router=None, periodo="7d", orden="bytes", limite=50) -> list[dict]
# orden ∈ {"bytes", "abonados"}
# [{"asn": 15169, "nombre": "GOOGLE", "pais": "US", "abonados": 3900, "pct_abonados": 92.6,
#   "flujos": 912345, "bytes_subida": 120000000, "bytes_bajada": 2400000000, "bytes": 2520000000}, ...]
# asn 0 = "sin ASN / no público"; -1 = "otros (agrupados)".

def top_puertos(con, categoria, router=None, periodo="7d", sentido="saliente", orden="abonados", limite=80) -> list[dict]
# orden ∈ {"abonados", "bytes", "flujos"}; sentido ∈ {"saliente", "entrante", "interna"}
# [{"sentido": "saliente", "proto": "tcp", "puerto": 443, "puerto_hasta": 443, "etiqueta": "tcp/443",
#   "servicio": "HTTPS", "abonados": 4100, "pct_abonados": 97.4, "flujos": 50123456,
#   "bytes_subida": 900000000, "bytes_bajada": 8000000000}, ...]

def top_puertos_exactos(con, categoria, router=None, periodo="7d", limite=100) -> list[dict]
# Puertos exactos de puerto_dia que caen en los cubos -1/-2 (lo que el catálogo no nombra), por flujos.
# [{"sentido": "saliente", "proto": "udp", "puerto": 27015, "servicio": "Steam / juegos Valve",
#   "flujos": 81234, "bytes": 51200000, "abonados_max_ventana": 37}, ...]

def top_consumidores(con, categoria, router=None, periodo="7d", orden="bajada", limite=50) -> list[dict]
# orden ∈ {"bajada", "subida", "total", "flujos"}
# [{"router": "core-a", "abonado": "100.64.1.10", "bytes_subida": 3400000000, "bytes_bajada": 41000000000,
#   "flujos": 812345, "dias_activo": 7, "max_flujos": 640, "max_ips": 210, "max_peers_udp": 12}, ...]

def percentiles_abonado(con, categoria, router=None, periodo="7d") -> dict[str, dict]
# Claves: "flujos", "tcp_nuevas", "udp", "ips", "puertos", "peers_udp", "syn". Sin datos → {}.
# {"tcp_nuevas": {"p50": 3, "p90": 18, "p99": 79, "p99.9": 249, "max": 3120, "n": 5020331}, ...}
# Unidad: por abonado y por MINUTO.

def senales(con, categoria, router=None, periodo="7d", limite=20) -> dict
# {"sensibles": {"tcp/25 SMTP (envío directo)": [{"router": "core-a", "abonado": "100.64.1.12",
#                 "flujos": 4410, "remotos_max_ventana": 38, "ventanas": 210, "ultima": "2026-10-09T21:14:00-05:00"}]},
#  "reflectores": {"udp/1900 entrante (posible reflector)": [ ...mismas claves... ]},
#  "barridos": [{"router": "core-a", "abonado": "100.64.1.14", "puerto": "tcp/23", "servicio": "Telnet",
#                "remotos_max_ventana": 60, "ventanas": 14, "ultima": "2026-10-09T03:02:00-05:00"}],
#  "p2p": [{"router": "core-a", "abonado": "100.64.1.16", "peers_udp_max": 120, "ventanas": 300,
#           "ultima": "2026-10-09T22:40:00-05:00"}],
#  "dns": [{"proto": "udp", "puerto": 53, "servidor": "192.0.2.53", "red": "AS64500 EJEMPLO (EC)",
#           "abonados": 900, "pct_abonados": 21.4, "flujos": 1203456}],
#  "destinos_no_publicos": [{"red": "10.9.9.0/24", "abonados": 3, "flujos": 120, "bytes": 51000}]}
# Las listas internas van ordenadas por flujos (o remotos) descendente y cortadas en `limite`.

def servicios_categoria(con, categoria, router=None, dias=7) -> dict
# Entrada del firewall. dias ≤ 14 (si no, ValueError). Abonados EXACTOS sobre el periodo (foto 7d o presencia).
# {"categoria": "residencial", "routers": ["core-a"], "desde": "2026-10-03", "hasta": "2026-10-09",
#  "dias_con_datos": 7, "abonados_total": 4210,
#  "filas": [{"sentido": "saliente", "proto": "tcp", "puerto": 25, "puerto_hasta": 25, "etiqueta": "tcp/25",
#             "servicio": "SMTP (envío directo)", "abonados": 12, "pct_abonados": 0.3, "flujos": 9120,
#             "bytes": 81200000, "dias_observado": 7}, ...]}

def salud(con, datos, horas=24) -> dict
# {"exportadores": [{"exportador": "192.0.2.1", "router": "core-a",          # router None = desconocido
#     "ultimo_archivo": "2026-10-10T20:41:00-05:00", "archivos": 1440, "flujos": 40100000,
#     "flujos_categoria": 39800000, "pct_fuera_categoria": 0.7, "secuencia_perdida": 0,
#     "bytes_subida": 1100000000, "bytes_bajada": 0, "errores": 0}],
#  "pendientes": 2, "en_error": 0, "descartados": 0,
#  "ultima_ejecucion": "2026-10-10T20:43:20-05:00",
#  "disco": {"total_bytes": 21000000000, "libre_bytes": 17500000000, "libre_pct": 83.3,
#            "crudo_bytes": 410000000, "db_bytes": 52000000, "estado": "ok"}}      # "ok" | "aviso" | "critico"

def ventanas_router(con, router, minutos=60) -> list[dict]
# Minuto a minuto, para comparar con los contadores de la interfaz en el router (cobertura, FastTrack, sentido).
# [{"ventana": "2026-10-10T20:40:00-05:00", "flujos_total": 28000, "flujos_categoria": 27900,
#   "bytes_subida": 18000000, "bytes_bajada": 0, "secuencia_perdida": 0, "estado": "ok"}, ...]

def interfaces_router(con, router, periodo="hoy") -> list[dict]
# [{"entrada": 7, "salida": 1, "flujos": 3100000, "bytes": 2100000000}, ...]   # ifIndex del router
```

Otras funciones de `flujos_db` (internas de A, B no las usa): `crear_esquema`, `guardar_archivo`,
`registrar_desconocido`, `cerrar_dias`, `retencion`, `actualizar_asn`, `estado_disco`.

### 5.4 Contrato de `mtp/flujos.py` (A; lo usa `trafico.py`)

```python
ROTACION = int(os.environ.get("ROTACION_NETFLOW", 60))
FORMATO = "csv:%pr,%sa,%sp,%da,%dp,%flg,%ipkt,%ibyt,%fl,%in,%out"
def leer_linea(linea: str) -> Flujo | None
def filtro_nfdump(cidrs: list[str]) -> str                 # "net 100.64.0.0/22 or net 198.51.100.0/26"
class Redes:  # de router["categorias"]; categoria_de(ip_int) -> str | None (bisect sobre rangos)
def observaciones(fl: Flujo, redes: Redes) -> list[Observacion]   # 0, 1 o 2; reglas de 1.1
def router_por_exportador(inv: dict, ip: str) -> str | None
class TablaAsn:  # TSV de iptoasn en array('I'); buscar(ip_int) -> int; nombres() -> iter[(asn, nombre, pais)]
def guardian(datos, con, *, ahora=None, uso=shutil.disk_usage, limites=None) -> dict
def procesar(datos, inventario: dict, *, ahora=None, espera=True, max_segundos=600,
             nfdump=("nfdump",)) -> dict
# nfdump = prefijo de argv inyectable: en pruebas (sys.executable, "tests/nfdump_falso.py").
# Devuelve {"procesados": int, "vacios": int, "errores": int, "desconocidos": int,
#           "pendientes": int, "dias_cerrados": [str], "guardian": {...}}
```

### 5.5 CLI nueva en `trafico.py` (A)

```
python trafico.py flujos-procesar [--max-segundos 600] [--sin-espera]
python trafico.py flujos-estado                         # JSON de salud()
python trafico.py flujos-consulta QUE --categoria C [--router R] [--periodo 7d] [--orden X] [--limite N] [--dias 7]
       # QUE ∈ resumen, por_hora, top_destinos, top_puertos, top_puertos_exactos, top_consumidores,
       #        percentiles_abonado, senales, servicios_categoria ; imprime JSON
python trafico.py flujos-cerrar-dia --dia AAAA-MM-DD      # fuerza recálculo del día
```

### 5.6 Lo que hace B

**Carga del módulo**: en `web.py`, `FLUJOS = None` y `_flujos()` que importa `mtp.flujos_db` la primera vez.
Las pruebas de B asignan `web.FLUJOS = FlujosFalso()` (clase con los mismos nombres de 5.3 que devuelve los
ejemplos de arriba tal cual). Así B programa y prueba sin esperar a A. Base: `Path(CFG["datos"]) / "flujos.db"`,
abierta con `abrir(..., solo_lectura=True)` por petición y cerrada al terminar. Sin base → tarjeta
"Todavía no hay datos NetFlow" con enlace a Panel → Exportar NetFlow.

**Navegación**: añadir `("/trafico", "Tráfico")` y `("/firewall", "Firewall")`.

**`/trafico?router=&categoria=&periodo=`** (validar: router vacío o del inventario, categoría `^[\w-]+$`,
periodo en `PERIODOS`; si no, el valor por defecto). Tarjetas:
1. Resumen (abonados, bytes subida/bajada, relación; aviso si `relacion_bajada_subida` es None o < 0,5:
   "no llega la bajada: Traffic Flow solo exporta lo que entra por las interfaces listadas; ver Documentación").
2. Por hora: barras en SVG en línea o `div` con ancho proporcional, sin librerías.
3. Top destinos (selector orden bytes/abonados). 4. Top puertos salientes. 5. Entrantes. 6. Puertos sin
   catálogo. 7. Top consumidores (selector bajada/subida/total/flujos). 8. Percentiles por abonado y minuto
   (misma tabla que el informe de conntrack, con la nota de unidad). 9. Señales, DNS, no públicos.
10. Salud: exportadores (desconocidos en rojo con el aviso de D4; `pct_fuera_categoria > 30` en ámbar con el
   aviso de D6; `secuencia_perdida > 0` = se pierden paquetes de exportación), pendientes, disco, y
   `ventanas_router` de la última hora con la explicación de cómo compararla con
   `/interface print stats` (6.3). 11. Interfaces (ifIndex) del router.

**`/firewall?router=&categoria=&dias=7`**: resultado de `firewall.clasificar` agrupado por clase con
conteos, avisos de evidencia insuficiente, y botón **Descargar propuesta** → `GET /firewall/propuesta.rsc?…`
(`Content-Type: text/plain; charset=utf-8`, `Content-Disposition: attachment; filename="firewall-<categoria>.rsc"`).
Nada se escribe en disco.

**Tarjeta Exportar NetFlow** (`comandos_netflow`): aplicar sección 2 (paso 0, `cache-entries`, `src-address`
con la IP del router si se elige router, `v9-template-timeout=1m`, comillas para nombres con espacios, quitar
condicional). Puerto: `int(os.environ.get("PUERTO_NETFLOW", PUERTO_NETFLOW))`.

**Routers**: rechazar al guardar un `exportador` (o `host` sin exportador) igual al de otro router: el colector
no podría distinguirlos.

**Documentación** (regla del proyecto: cada función nueva se documenta en el panel): qué es NetFlow aquí,
cómo se configura el router, qué significa cada tabla, unidad "por minuto", subida/bajada y el caso "solo
entrada", FastTrack/hw-offload, retenciones, exportador desconocido, y la diferencia conntrack (concurrencia →
`connection-limit`) vs NetFlow (tasa → `dst-limit`).

**`mtp/firewall.py`**:

```python
PCT_ESENCIAL = 5.0          # ≥ 5 % de los abonados de la categoría en 7 días
PCT_USADO = 0.5             # 0,5 % – 5 %
MIN_DIAS = 7
MIN_ABONADOS = 50
NUNCA_BLOQUEAR = {...}      # del agente: tcp 80/443, udp/443, udp 53 y 123 salientes, udp 3478-3481,
                            # udp 19302-19309, udp 500/4500, udp+tcp 1194, udp 51820, tcp 1723 + proto gre,
                            # tcp 465/587/993/995, tcp+udp 853 (marcado "decisión de política DNS")
RIESGO_SALIENTE = {...}     # tcp 25, 23, 2323, 135, 139, 445; udp 137, 138; tcp 16464-16471
RIESGO_ENTRANTE = {...}     # udp 53, 123, 1900, 11211, 19, 389, 161, 5353; tcp 23, 2323, 135, 139, 445, 3389, 5900, 7547, 8291, 8728

def clasificar(servicios: dict, percentiles: dict | None = None) -> dict
# servicios = flujos_db.servicios_categoria(...). Devuelve el mismo dict más
#   "suficiente": bool, "motivo_insuficiente": str | None,
#   y en cada fila "clase": "esencial"|"usado"|"minoritario"|"riesgo"|"no_observado", "revisar": bool, "motivo": str.
# Reglas en orden: (sentido, proto, puerto..puerto_hasta) solapa RIESGO_* → "riesgo" (revisar=True si pct ≥ PCT_ESENCIAL);
# solapa NUNCA_BLOQUEAR o pct ≥ PCT_ESENCIAL → "esencial"; pct ≥ PCT_USADO → "usado"; si no → "minoritario".
# Además una fila "no_observado" (abonados 0) por cada entrada de RIESGO_* y del catálogo exacto que no aparezca.
# suficiente = dias_con_datos ≥ MIN_DIAS y abonados_total ≥ MIN_ABONADOS.

def propuesta_rsc(clasificacion: dict, percentiles: dict, prefijo: str | None = None,
                  lista: str | None = None, limite_conexiones: int | None = None, fecha: str | None = None) -> str
# prefijo por defecto: "RES" para residencial, "EMP" para empresarial, la categoría en mayúsculas si no.
# lista por defecto: "CAT-" + categoría en mayúsculas. Sin IPs: la address-list se deja comentada para el operador.

def main(argv=None) -> int
# python3 -m mtp.firewall --datos DIR --categoria residencial [--router X] [--dias 7] [--salida F] [--forzar]
# Sin evidencia suficiente: sale 1 con el motivo, salvo --forzar (entonces la cabecera lo advierte).
```

Forma de la propuesta (sintaxis válida en 6.49 y 7.x; comentarios con la evidencia de cada regla):

```
# Propuesta firewall residencial — mikrotik-traffic-profiler (NetFlow)
# Evidencia: core-a, 2026-10-03..2026-10-09 (7 días), 4210 abonados activos.
# MODO DETECCIÓN: cada regla añade a una lista DET-RES-*; el drop gemelo va disabled=yes.
# Despliegue: respaldo → Safe Mode → UN core canario → revisar contadores 7 días → activar drops → flota.
/ip firewall address-list
# add list=CAT-RESIDENCIAL address=<rango residencial> comment="RES: rango residencial"
/ip firewall filter
add chain=forward action=jump jump-target=RES-SALIDA src-address-list=CAT-RESIDENCIAL connection-state=new comment="RES: capa salida"
add chain=forward action=jump jump-target=RES-ENTRADA dst-address-list=CAT-RESIDENCIAL connection-state=new comment="RES: capa entrada"
add chain=RES-SALIDA action=return src-address-list=RES-EXCEPCION comment="RES: excepciones por abonado"
add chain=RES-SALIDA action=add-src-to-address-list address-list=DET-RES-TCP25 address-list-timeout=1d protocol=tcp dst-port=25 comment="RES: SMTP directo (evidencia: 12 abonados, 0.3 %, 7 d)"
add chain=RES-SALIDA action=drop protocol=tcp dst-port=25 disabled=yes comment="RES: SMTP directo DROP (activar tras revisión)"
# … una pareja por fila "riesgo" observada; las "riesgo" no observadas van comentadas como bloqueo preventivo opcional;
# las "riesgo" con revisar=True van solo comentadas ("masivo: decidir a mano").
add chain=RES-SALIDA action=jump jump-target=RES-RAFAGA protocol=tcp tcp-flags=syn comment="RES: ráfaga de conexiones nuevas"
add chain=RES-RAFAGA action=return dst-limit=498/1m,498,src-address/5m comment="RES: límite = 2 × p99.9 tcp_nuevas por minuto (249)"
add chain=RES-RAFAGA action=add-src-to-address-list address-list=DET-RES-RAFAGA address-list-timeout=1d comment="RES: excede ráfaga"
add chain=RES-RAFAGA action=drop disabled=yes comment="RES: ráfaga DROP (activar tras revisión)"
# con limite_conexiones (p99.9 de conntrack × 2, del informe de conntrack):
# add chain=RES-SALIDA action=add-src-to-address-list address-list=DET-RES-CONEX address-list-timeout=1d protocol=tcp connection-limit=N,32 comment="RES: …"
add chain=RES-SALIDA action=return comment="RES: fin capa salida"
add chain=RES-ENTRADA action=accept connection-nat-state=dstnat comment="RES: port-forwards contratados"
add chain=RES-ENTRADA action=add-dst-to-address-list address-list=DET-RES-ENTRANTE address-list-timeout=1d comment="RES: entrante nuevo sin dst-nat"
add chain=RES-ENTRADA action=drop disabled=yes comment="RES: entrante DROP (activar tras revisión)"
# Rollback: /ip firewall filter remove [find comment~"^RES:"]
```

**Agente** (`.claude/agents/trafico-mikrotik.md`): NetFlow pasa a ser la fuente principal
(`trafico.py flujos-consulta …` por SSH en el servidor, `python3 -m mtp.firewall`); conntrack queda para
concurrencia; la configuración de Traffic Flow solo se **propone** (tarjeta del panel), nunca se aplica.
**README**: arquitectura, puertos, retención, servicios nuevos, límites (sección 7).

---

## 6. Pruebas

Todas de comportamiento (qué sale con una entrada dada), en `tests/`, con `python -m unittest discover -s tests -t .`.
Deben pasar en Windows (sin nfdump: las que lo necesitan hacen `skipTest`) y en Debian.

### 6.1 Constructor A

`tests/nfdump_falso.py`: imita `nfdump` para las pruebas. Con `-I -r X` imprime el bloque de `PrintStat`
leyendo `X.stat` (si no existe, `Flows: <líneas>`); con `-o csv:… -r X` imprime la cabecera y las líneas de
`X` (un archivo de texto con las líneas CSV); si `X` contiene la línea `#ERROR`, imprime lo anterior y sale
con 255 (archivo truncado); si contiene `#DORMIR n`, duerme n segundos (vigilante).

`tests/test_flujos.py`:
- `leer_linea`: cabecera → None; TCP; ICMP `8.0`; IPv6 → None; línea corta → None.
- Reglas 1.1: cliente→443 saliente; respuesta 443→cliente saliente (lado dst, bytes de bajada); servidor web en
  el abonado (remoto alto → abonado:80) entrante; 53↔53 saliente; dos puertos altos (menor gana); ICMP
  petición/respuesta/error; GRE; interna; residencial→empresarial = dos observaciones.
- `servicios.clave`: 443 → 443, 3479 → 3478, 40000 → -1, 50000 → -2, ICMP → 0; `etiqueta` de cada uno.
- Agregación de un archivo con el **escenario base** (abajo): abonados por servicio, barrido de 60 destinos a
  tcp/23, P2P de 120 pares, DNS a 192.0.2.53, no público 10.9.9.0/24, señal tcp/25, reflector udp/1900,
  `tcp_nuevas` y `syn`.
- `router_por_exportador`: por `exportador`, por `host`, desconocido.
- `filtro_nfdump` con varios CIDR.
- `TablaAsn` con un TSV de 3 rangos (incluye ASN 0 descartado).

`tests/test_flujos_db.py`:
- **Vacío**: base nueva → todas las consultas de 5.3 devuelven listas vacías/ceros y `json.dumps` funciona.
- **Idempotencia**: procesar el mismo directorio dos veces → contadores idénticos; un archivo `ok` que cambia
  de tamaño no se suma otra vez.
- **Archivo a medias**: `#ERROR` → `ROLLBACK` (ningún contador cambia), `reintentar`, y `error` al tercer intento.
- **Archivo no listo**: ventana reciente con `espera=True` → no se procesa; con `--sin-espera` sí.
- **Exportador desconocido**: directorio `198-51-100-77` → fila en `exportador_desconocido`, aparece en
  `salud()` con `router=None`, no suma nada.
- **Cierre de día**: abonados exactos por servicio; poda a -1/-2; foto 7d; archivo tardío marca `sucio` y el
  recálculo deja la cifra correcta.
- **Mismo abonado en dos routers** cuenta como dos en `router=None`.
- **Percentiles** desde histograma contra un cálculo directo (error ≤ 10 %, nunca por debajo).
- **Retención**: con `ahora` inyectado, cada tabla borra justo lo que dice 3.6.
- **Guardián / disco lleno**: con `uso` falso: (a) borra procesados viejos; (b) bajo el mínimo borra
  procesados recientes; (c) bajo el crítico borra sin procesar y los marca `descartado`; nunca borra
  `nfcapd.current.<pid>` de un pid vivo.
- **Tope de memoria**: archivo con más claves que el tope (tope inyectable) → `error` "demasiado grande".

`tests/emisor_netflow.py` (CLI y biblioteca, solo stdlib): arma paquetes NetFlow **v5** (cabecera 24 B +
registros 48 B) y **v9** (FlowSet de plantilla id 0 con plantilla 256: IN_BYTES 1/4, IN_PKTS 2/4, PROTOCOL 4/1,
TCP_FLAGS 6/1, L4_SRC_PORT 7/2, IPV4_SRC_ADDR 8/4, INPUT_SNMP 10/2, L4_DST_PORT 11/2, IPV4_DST_ADDR 12/4,
OUTPUT_SNMP 14/2, LAST_SWITCHED 21/4, FIRST_SWITCHED 22/4; luego FlowSets de datos) y los manda por UDP.
`python3 tests/emisor_netflow.py --destino 127.0.0.1 --puerto 2055 --version 9 --escenario base --repeticiones 1`.
**Escenario base** (el mismo de `tests/test_analizar.py`, con su registro de respuesta cuando corresponde):
abonados 100.64.1.10–16; HTTPS, QUIC, tcp/25, barrido tcp/23 a 60 destinos con solo SYN, DNS a 192.0.2.53,
10.9.9.9:80, 120 pares UDP, entrante a 100.64.1.13:80, y un udp/1900 entrante a 100.64.1.17.

`tests/test_extremo_netflow.py` (`skipTest` si no hay `nfcapd`): carpeta temporal, `nfcapd -C none -4 -M dir
-p <puerto libre> -t 2`, emisor v9 y v5 contra 127.0.0.1, esperar 2 rotaciones, parar nfcapd (SIGTERM),
inventario con `exportador: 127.0.0.1`, `procesar(..., espera=False)` con el `nfdump` real, y comprobar con
las consultas de 5.3 las mismas cifras del escenario base.

### 6.2 Constructor B

`tests/test_firewall.py`: clasificación en cada frontera (5,0 % / 4,9 % / 0,5 % / 0,49 %); riesgo masivo →
`revisar`; `no_observado`; evidencia insuficiente (6 días, 49 abonados) → `suficiente=False` y `main` sale 1
sin `--forzar`; la propuesta contiene la pareja detección + drop `disabled=yes` por cada riesgo observado, ninguna
IP, el `dst-limit` = `2 × p99.9` redondeado hacia arriba, el rollback, y es igual para la misma entrada (sin
fechas variables salvo `fecha`).

`tests/test_web_trafico.py` con `web.FLUJOS = FlujosFalso()`: sin sesión → 303; `/trafico` y `/firewall` 200
con datos falsos (ASN, puerto, abonado, aviso de exportador desconocido, aviso de bajada ausente cuando
`relacion_bajada_subida` es None); parámetros inválidos (`periodo=x`, `router=../../`) no rompen ni se reflejan
sin escapar; sin base → tarjeta "Todavía no hay datos NetFlow"; descarga `.rsc` con `Content-Disposition`;
el HTML escapa un nombre de ASN con `<script>`.

`tests/test_web.py`: actualizar `test_comandos_netflow` a la sección 2 (paso 0, `cache-entries=128k`,
`src-address`, `v9-template-timeout=1m`, quitar condicional, sin `set enabled=no` suelto); rechazo de
exportador duplicado en Routers.

### 6.3 Verificación extremo a extremo en el servidor (coordinador, con aprobación del operador)

Antes: respaldo `tar.gz` de `/etc/mikrotik-traffic-profiler` y `/var/lib/mikrotik-traffic-profiler`
(sin `data/nfcapd`) en `/root/backups/`.

1. `git pull` + `bash deploy/install.sh`. Comprobar: `ss -ulnp | grep 2055` muestra **un** `nfcapd` del
   usuario `mtp`; `systemctl is-active mtp-colector mtp-flujos.timer`; `/etc/nfdump/default.conf` con
   `options=''`; `systemd-analyze verify` de las unidades nuevas.
2. **Sintético**, sin tocar los datos reales: como `mtp`, en `/var/lib/mikrotik-traffic-profiler/prueba-e2e/`,
   un `nfcapd` aparte en otro puerto (p. ej. 2057) + `tests/emisor_netflow.py` v9 a 127.0.0.1 +
   `trafico.py --datos prueba-e2e --inventario prueba-e2e/inv.json flujos-procesar --sin-espera` +
   `flujos-consulta` de cada tipo: deben salir las cifras del escenario base. Luego `python3 -m mtp.web` con
   `--datos prueba-e2e` en otro puerto y revisar `/trafico` y `/firewall`. Borrar `prueba-e2e/`.
3. **Real**: el router de pruebas que **ya exporta v9** al servidor (hoy pocos registros, nada escuchando):
   - darlo de alta en Routers con `exportador` = la IP con la que llega (si no, aparecerá como desconocido:
     es la prueba de D4) y sus rangos;
   - en ≤ 3 minutos debe aparecer en Tráfico → Salud con archivos por minuto; si llegan archivos pero 0 flujos,
     es la plantilla v9 aún no recibida (`v9-template-timeout`);
   - `flujos_categoria` vs `flujos_total`: si casi todo queda fuera de categoría, faltan rangos o la interfaz no
     es la de clientes.
4. **Cobertura** (canario, con el operador mirando el router, 10 minutos): anotar `/interface print stats` de
   la interfaz de clientes al inicio y al final; comparar `rx-byte` (subida de los abonados) con la suma de
   `bytes_subida` de `ventanas_router` en esos minutos, y `tx-byte` (bajada) con `bytes_bajada`.
   - subida ≈ rx y bajada ≈ 0 → Traffic Flow solo exporta lo que **entra** por la interfaz: las conexiones se
     ven todas, la bajada no. Decisión del operador (sección 7).
   - subida y bajada muy por debajo → FastTrack o hw-offload no se están exportando: repetir con un abonado de
     prueba excluido de FastTrack para confirmarlo.
5. Esperar el primer cierre de día (02:00) y comprobar `servicio_7d`/`activos_7d`, retención y tamaño de la base.

---

## 7. Riesgos y límites

- **Volumen**: si alguien pone la WAN en `interfaces=`, el volumen se multiplica. Defensas: `% fuera de
  categoría` en Salud, tope de claves por archivo, guardián de disco. El síntoma de la vez anterior (servidor
  colgado) aquí se convierte en archivos `error` y crudo borrado, no en un OOM.
- **Solo entrada (por confirmar)**: si Traffic Flow exporta solo lo que entra por las interfaces listadas, con
  la interfaz de clientes se ve toda conexión iniciada o contestada por el abonado, pero no la bajada ni los
  intentos entrantes que el abonado no contesta. Alternativas para el operador: aceptarlo (alcanza para el
  firewall de salida), o añadir la WAN con `packet-sampling` (solo v7), sabiendo que el muestreo deforma "% de
  abonados" y la tasa por abonado.
- **FastTrack / hw-offload**: lo acelerado por hardware no se exporta (oficial); FastTrack por software está en
  duda (documentación contradictoria). Se mide en 6.3.4.
- **Pérdida de paquetes UDP** del export: se ve en `secuencia_perdida`. Un reinicio del colector pierde hasta
  la siguiente plantilla v9.
- **Colector abierto**: cualquiera que alcance UDP 2055 crea un directorio con `-M`. Se registra como
  desconocido y se borra a la hora; la VM no tiene firewall. Si se quiere cerrar, es una decisión aparte
  (nftables con las IP del inventario).
- **Lo que NetFlow no puede saber**: el dominio (DoH/DoT/ECH esconden incluso el SNI; NetFlow no ve nombres);
  CDN compartidas (Google, Meta, Akamai, Cloudflare: un ASN sirve cientos de servicios: "AS15169" no es
  "YouTube"); VPN y túneles (todo va a un solo destino/puerto); el contenido; el usuario detrás del CPE (un
  abonado = una IP privada; varios equipos de la casa son uno); IPv6 (no se procesa en esta fase); la
  concurrencia exacta de conexiones (para `connection-limit`, usar el p99.9 de conntrack); QUIC y
  conexiones TCP largas se parten cada minuto (por eso `flujos` cuenta 5-tuplas distintas por minuto).
- **Sentido inferido**: entre dos puertos altos (P2P, juegos) el "menor gana" puede invertir cliente/servidor;
  esos casos caen en los cubos -1/-2 y no cambian decisiones de firewall.
- **Abonados distintos en 30 días** no son exactos (máximo diario); en 7 días sí.
- **Cambios de rangos en el inventario** se aplican desde el siguiente archivo; lo ya agregado no se reclasifica.

---

## Fuentes

- [T1] Traffic Flow — RouterOS (help.mikrotik.com): https://help.mikrotik.com/docs/spaces/ROS/pages/21102653/Traffic+Flow
- [T2] Traffic Flow — manual 7.25: https://manual.mikrotik.com/docs/7.25/diagnostics-monitoring-and-troubleshooting/traffic-flow/
- [T3] Packet Flow in RouterOS (sección FastTrack): https://help.mikrotik.com/docs/spaces/ROS/pages/328227/Packet+Flow+in+RouterOS
- [T4] Wiki v6 FastTrack ("restriction removed in 6.33"; hoy redirige): https://wiki.mikrotik.com/wiki/Manual:IP/Fasttrack
- [T5] Traffic Flow RouterOS 3.0 (sintaxis antigua `address=IP:puerto`): https://mikrotik.com/testdocs/ros/3.0/aaa/traffic-flow.pdf ; la wiki v6 https://wiki.mikrotik.com/wiki/Manual:IP/Traffic_Flow ya no está disponible.
- [T6] Foro MikroTik, "NetFlow not capturing egress data" (no oficial): https://forum.mikrotik.com/t/netflow-not-capturing-egress-data/39273
- [T7] FastNetMon, configuración MikroTik (cache-entries 128k, src-address): https://fastnetmon.com/docs-fnm-advanced/mikrotik/
- [T8] MUM, "MikroTik Traffic Flow Network Monitoring / PRTG" (v5 solo entrada): https://mum.mikrotik.com/presentations/LB19/presentation_6352_1548734037.pdf
- [N1] nfdump 1.7.5-2+deb13u1, fuentes Debian: https://sources.debian.org/src/nfdump/1.7.5-2+deb13u1/ — `man/nfcapd.1`, `man/nfdump.1`, `man/nfexpire.1`, `debian/default.conf`, `debian/nfdump-generator`, `debian/nfdump@.service`, `src/nfcapd/nfcapd.c`, `src/collector/collector.c`, `src/output/output_csv.c`, `src/libnffile/nffile.c`. Proyecto: https://github.com/phaag/nfdump
