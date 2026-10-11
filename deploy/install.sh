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

echo "== usuario de servicio mtp"
if ! id mtp >/dev/null 2>&1; then
  useradd --system --home-dir "$VAR" --shell /usr/sbin/nologin mtp
fi
usermod -aG systemd-journal mtp

echo "== carpetas"
install -d -o root -g mtp -m 0750 "$ETC"
install -d -o mtp -g mtp -m 0750 "$VAR" "$VAR/data"
install -d -o mtp -g mtp -m 0700 "$VAR/.ssh"

echo "== llave SSH para los routers (RSA 4096: RouterOS 6 no acepta ed25519)"
if [ ! -f "$VAR/.ssh/id_rsa" ]; then
  runuser -u mtp -- ssh-keygen -q -t rsa -b 4096 -N "" -C "mtp@$(hostname)" -f "$VAR/.ssh/id_rsa"
fi

echo "== configuración"
if [ ! -f "$ETC/inventario.json" ]; then
  printf '{\n  "maximo_conexiones_por_cidr": 150000,\n  "routers": {}\n}\n' > "$ETC/inventario.json"
fi
chown root:mtp "$ETC/inventario.json"; chmod 0640 "$ETC/inventario.json"

if [ ! -f "$ETC/mtp.env" ]; then
  printf 'PUERTO_WEB=%s\nCATEGORIA=residencial\nREPETIR=4\nINTERVALO=15\n' "$PUERTO" > "$ETC/mtp.env"
fi
chown root:mtp "$ETC/mtp.env"; chmod 0640 "$ETC/mtp.env"

CLAVE_NUEVA=""
if [ ! -f "$ETC/web.json" ]; then
  CLAVE_NUEVA="$(python3 -c 'import secrets; print(secrets.token_urlsafe(15))')"
  printf '%s\n' "$CLAVE_NUEVA" | (cd "$APP" && python3 -m mtp.web --config "$ETC/web.json" --cambiar-clave >/dev/null)
fi
chown root:mtp "$ETC/web.json"; chmod 0640 "$ETC/web.json"

echo "== tabla IP→ASN"
runuser -u mtp -- python3 "$APP/trafico.py" --datos "$VAR/data" asn || echo "aviso: no se pudo descargar ip2asn; se reintenta cada noche"

echo "== systemd"
install -m 0644 "$APP"/deploy/systemd/mtp-* /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now mtp-web.service mtp-analizar.timer
systemctl restart mtp-web.service

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Panel:   http://$IP:$(grep -oP '^PUERTO_WEB=\K.*' "$ETC/mtp.env")  (usuario admin)"
if [ -n "$CLAVE_NUEVA" ]; then
  echo "Clave:   $CLAVE_NUEVA   (se muestra solo esta vez; cambiarla con --cambiar-clave)"
fi
echo "Llave pública para el usuario 'trafico' de cada router:"
cat "$VAR/.ssh/id_rsa.pub"
echo
echo "Al agregar un router al inventario: systemctl enable --now mtp-recolectar@<router>.timer"
