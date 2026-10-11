#!/usr/bin/env bash
# Instala mikrotik-traffic-profiler en Debian 12/13 desde el clon en /opt/mikrotik-traffic-profiler.
#   git clone https://github.com/mtandazo35/mikrotik-traffic-profiler /opt/mikrotik-traffic-profiler
#   bash /opt/mikrotik-traffic-profiler/deploy/install.sh [--puerto 8080]
# Idempotente: no pisa inventario, clave del panel ni llave SSH si ya existen.
set -euo pipefail

APP=/opt/mikrotik-traffic-profiler
ETC=/etc/mikrotik-traffic-profiler
VAR=/var/lib/mikrotik-traffic-profiler
PUERTO=8080

while [ $# -gt 0 ]; do
  case "$1" in
    --puerto) PUERTO="$2"; shift 2 ;;
    *) echo "opción desconocida: $1" >&2; exit 1 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "ejecutar como root" >&2; exit 1; }
[ -f "$APP/trafico.py" ] || { echo "no está el código en $APP" >&2; exit 1; }
command -v python3 >/dev/null || { echo "falta python3" >&2; exit 1; }
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' || { echo "hace falta Python 3.10+" >&2; exit 1; }
command -v ssh >/dev/null || apt-get install -y openssh-client

echo "== nfdump (colector NetFlow)"
if ! command -v nfcapd >/dev/null; then
  apt-get install -y nfdump || { apt-get update && apt-get install -y nfdump; }
fi
# El paquete de Debian arranca su propio nfcapd como root en UDP 2055 (nfdump@default.service, que un generador
# de systemd crea desde /etc/nfdump/default.conf si "options" no está vacío): choca con mtp-colector y no tiene
# retención. Se para y se deja options='' (copia del original en default.conf.antes-mtp, una sola vez).
CONF_NFDUMP=/etc/nfdump/default.conf
systemctl stop 'nfdump@default.service' >/dev/null 2>&1 || true
systemctl disable --now nfdump.service >/dev/null 2>&1 || true   # paquetes viejos con unidad fija
if [ -f "$CONF_NFDUMP" ] && grep -Eq "^[[:space:]]*options=[\"']?[^\"'[:space:]]" "$CONF_NFDUMP"; then
  [ -f "$CONF_NFDUMP.antes-mtp" ] || cp -p "$CONF_NFDUMP" "$CONF_NFDUMP.antes-mtp"
  sed -i -E "s|^[[:space:]]*options=.*|# desactivado por mikrotik-traffic-profiler: usa mtp-colector.service\noptions=''|" "$CONF_NFDUMP"
fi
systemctl daemon-reload
systemctl stop 'nfdump@default.service' >/dev/null 2>&1 || true

echo "== usuario de servicio mtp"
if ! id mtp >/dev/null 2>&1; then
  useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin mtp
fi
usermod -aG systemd-journal mtp

echo "== carpetas"
install -d -o root -g mtp -m 0750 "$ETC"
install -d -o mtp -g mtp -m 0750 "$VAR" "$VAR/data" "$VAR/data/nfcapd"
install -d -o mtp -g mtp -m 0700 "$VAR/.ssh"

echo "== llave SSH para los routers (RSA 4096: RouterOS 6 no acepta ed25519)"
if [ ! -f "$VAR/.ssh/id_rsa" ]; then
  runuser -u mtp -- ssh-keygen -q -t rsa -b 4096 -N "" -C "mtp@$(hostname)" -f "$VAR/.ssh/id_rsa"
fi

echo "== configuración"
# El inventario lo edita el panel (usuario mtp, sin acceso de escritura a /etc): vive en $VAR.
if [ -f "$ETC/inventario.json" ] && [ ! -f "$VAR/inventario.json" ]; then
  mv "$ETC/inventario.json" "$VAR/inventario.json"
fi
if [ ! -f "$VAR/inventario.json" ]; then
  printf '{\n  "maximo_conexiones_por_cidr": 150000,\n  "routers": {}\n}\n' > "$VAR/inventario.json"
fi
chown mtp:mtp "$VAR/inventario.json"; chmod 0640 "$VAR/inventario.json"

if [ ! -f "$ETC/mtp.env" ]; then
  printf 'PUERTO_WEB=%s\nCATEGORIA=residencial\nREPETIR=4\nINTERVALO=15\n' "$PUERTO" > "$ETC/mtp.env"
fi
# variables de NetFlow que falten (sin pisar las que ya estén)
[ -z "$(tail -c1 "$ETC/mtp.env")" ] || echo >> "$ETC/mtp.env"
for par in PUERTO_NETFLOW=2055 ROTACION_NETFLOW=60 CRUDO_HORAS=6 CRUDO_MAX_GB=6 DISCO_MIN_LIBRE_PCT=15 DISCO_CRITICO_PCT=8; do
  grep -q "^${par%%=*}=" "$ETC/mtp.env" || printf '%s\n' "$par" >> "$ETC/mtp.env"
done
chown root:mtp "$ETC/mtp.env"; chmod 0640 "$ETC/mtp.env"
PUERTO_NF="$(grep -oP '^PUERTO_NETFLOW=\K[0-9]+' "$ETC/mtp.env" || echo 2055)"

echo "== buffer UDP para NetFlow (nfcapd -B 8 MiB; sin root el kernel lo recorta a rmem_max)"
printf 'net.core.rmem_max = 8388608\n' > /etc/sysctl.d/60-mtp-netflow.conf
sysctl -q -p /etc/sysctl.d/60-mtp-netflow.conf || echo "aviso: no se pudo aplicar net.core.rmem_max"

CLAVE_NUEVA=""
if [ ! -f "$ETC/web.json" ]; then
  CLAVE_NUEVA="$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')"
  printf '%s\n' "$CLAVE_NUEVA" | (cd "$APP" && python3 -m mtp.web --config "$ETC/web.json" --cambiar-clave >/dev/null)
fi
chown root:mtp "$ETC/web.json"; chmod 0640 "$ETC/web.json"

echo "== tabla IP→ASN"
runuser -u mtp -- python3 "$APP/trafico.py" --datos "$VAR/data" asn || echo "aviso: no se pudo descargar ip2asn; se reintenta cada noche"

echo "== systemd"
# versiones anteriores usaban un timer por router (mtp-recolectar@<router>.timer)
systemctl disable --now 'mtp-recolectar@*.timer' >/dev/null 2>&1 || true
rm -f '/etc/systemd/system/mtp-recolectar@.service' '/etc/systemd/system/mtp-recolectar@.timer'
COLECTOR_ANTES="$(sha256sum /etc/systemd/system/mtp-colector.service 2>/dev/null || true)"
install -m 0644 "$APP"/deploy/systemd/mtp-* /etc/systemd/system/
systemctl daemon-reload
# nada más debe escuchar en el puerto NetFlow (salvo nuestro colector, si ya corre)
PROPIO="$(systemctl show -p MainPID --value mtp-colector.service 2>/dev/null || echo 0)"
for pid in $(ss -Hulnp "sport = :$PUERTO_NF" 2>/dev/null | grep -oP 'pid=\K[0-9]+' | sort -u || true); do
  if [ "$pid" != "$PROPIO" ]; then
    echo "UDP $PUERTO_NF ya lo usa otro proceso (no es mtp-colector); pararlo antes de seguir:" >&2
    ss -ulnp "sport = :$PUERTO_NF" >&2 || true
    exit 1
  fi
done
systemctl enable --now mtp-web.service mtp-analizar.timer mtp-recolectar.timer mtp-colector.service mtp-flujos.timer
systemctl restart mtp-web.service
if [ -n "$COLECTOR_ANTES" ] && [ "$COLECTOR_ANTES" != "$(sha256sum /etc/systemd/system/mtp-colector.service)" ]; then
  systemctl restart mtp-colector.service   # la unidad cambió: aplicar (se pierden unos segundos de NetFlow)
fi

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Panel:   http://$IP:$(grep -oP '^PUERTO_WEB=\K.*' "$ETC/mtp.env")  (usuario admin)"
if [ -n "$CLAVE_NUEVA" ]; then
  echo "Clave:   $CLAVE_NUEVA   (se muestra solo esta vez; cambiarla con --cambiar-clave)"
fi
echo "Llave pública para el usuario 'trafico' de cada router:"
cat "$VAR/.ssh/id_rsa.pub"
echo
echo "Los routers se agregan en el panel → Routers; el muestreo se activa por router desde ahí."
echo "NetFlow: UDP $PUERTO_NF en esta IP ($IP); los routers se configuran con la tarjeta Exportar NetFlow del panel."
