#!/usr/bin/env bash
# One-shot HTTPS setup for the LensIQ dashboard (self-signed cert for the IP).
# Run on the VM as root:   sudo bash nginx/setup-https.sh
set -e

IP="129.159.20.37"
SSL_DIR="/etc/nginx/ssl"
CONF_SRC="$(dirname "$0")/lensiq.conf"

echo "==> Installing nginx (if missing)"
if ! command -v nginx >/dev/null; then
  apt-get update -y && apt-get install -y nginx
fi

echo "==> Generating self-signed certificate for IP $IP (valid 825 days)"
mkdir -p "$SSL_DIR"
openssl req -x509 -nodes -days 825 -newkey rsa:2048 \
  -keyout "$SSL_DIR/lensiq.key" -out "$SSL_DIR/lensiq.crt" \
  -subj "/CN=$IP" -addext "subjectAltName=IP:$IP"

echo "==> Installing nginx site"
cp "$CONF_SRC" /etc/nginx/sites-available/lensiq.conf
ln -sf /etc/nginx/sites-available/lensiq.conf /etc/nginx/sites-enabled/lensiq.conf
rm -f /etc/nginx/sites-enabled/default

echo "==> Opening firewall for 80 + 443"
iptables -I INPUT 6 -p tcp --dport 80  -j ACCEPT || true
iptables -I INPUT 6 -p tcp --dport 443 -j ACCEPT || true
command -v netfilter-persistent >/dev/null && netfilter-persistent save || true

echo "==> Testing + reloading nginx"
nginx -t
systemctl enable nginx
systemctl restart nginx

echo
echo "DONE.  Open:  https://$IP"
echo "It's a self-signed cert, so the browser shows a one-time 'Not secure' warning"
echo "→ click Advanced → Proceed. After that the camera QR scanner works."
echo
echo "NOTE: keep the LensIQ backend (7788) + frontend (7789) running via pm2."
echo "The desktop TOOL still talks to http://$IP:7788 directly (unaffected)."
