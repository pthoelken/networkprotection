#!/usr/bin/env bash

set -Eeuo pipefail

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SOURCE_DIR
readonly INSTALL_DIR="/opt/networkprotection"
readonly CONFIG_DIR="/etc/networkprotection"
readonly REQUIRED_PACKAGES=(
    iptables ipset curl util-linux gzip python3
)

(( EUID == 0 )) || { echo "Bitte als root ausführen." >&2; exit 1; }
command -v systemctl >/dev/null 2>&1 || { echo "systemd wurde nicht gefunden." >&2; exit 1; }

command -v apt-get >/dev/null 2>&1 || {
    echo "Dieses Installationsskript benötigt apt-get (Debian/Ubuntu)." >&2
    exit 1
}
command -v dpkg-query >/dev/null 2>&1 || {
    echo "dpkg-query wurde nicht gefunden." >&2
    exit 1
}

missing_packages=()
for package in "${REQUIRED_PACKAGES[@]}"; do
    if [[ "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" != "installed" ]]; then
        missing_packages+=("$package")
    fi
done

if (( ${#missing_packages[@]} > 0 )); then
    echo "Installiere fehlende Pakete: ${missing_packages[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_packages[@]}"
else
    echo "Alle benötigten Pakete sind bereits installiert."
fi

install -d -m 0755 "$INSTALL_DIR" "$CONFIG_DIR"
install -m 0755 "$SOURCE_DIR/networkprotection.sh" "$INSTALL_DIR/networkprotection.sh"
install -m 0755 "$SOURCE_DIR/geoip_to_cidrs.py" "$INSTALL_DIR/geoip_to_cidrs.py"
install -m 0755 "$SOURCE_DIR/asndrop_to_prefixes.py" "$INSTALL_DIR/asndrop_to_prefixes.py"
install -m 0755 "$SOURCE_DIR/normalize_cidrs.py" "$INSTALL_DIR/normalize_cidrs.py"
install -m 0644 "$SOURCE_DIR/VERSION" "$INSTALL_DIR/VERSION"
echo "Installierte Network-Protection-Version: $("$INSTALL_DIR/networkprotection.sh" --version)"

if [[ ! -e "$CONFIG_DIR/networkprotection.conf" ]]; then
    install -m 0644 "$SOURCE_DIR/networkprotection.conf" "$CONFIG_DIR/networkprotection.conf"
else
    echo "Bestehende Konfiguration bleibt erhalten: $CONFIG_DIR/networkprotection.conf"
fi
if [[ ! -e "$CONFIG_DIR/custom-blacklist.txt" ]]; then
    install -m 0644 "$SOURCE_DIR/custom-blacklist.txt" "$CONFIG_DIR/custom-blacklist.txt"
else
    echo "Bestehende Custom-Liste bleibt erhalten: $CONFIG_DIR/custom-blacklist.txt"
fi
if [[ ! -e "$CONFIG_DIR/whitelist.txt" ]]; then
    install -m 0644 "$SOURCE_DIR/whitelist.txt" "$CONFIG_DIR/whitelist.txt"
else
    echo "Bestehende Whitelist bleibt erhalten: $CONFIG_DIR/whitelist.txt"
fi

install -m 0644 "$SOURCE_DIR/systemd/networkprotection.service" /etc/systemd/system/networkprotection.service
install -m 0644 "$SOURCE_DIR/systemd/networkprotection.timer" /etc/systemd/system/networkprotection.timer
if [[ -f /etc/modules-load.d/networkprotection.conf ]] && \
    [[ "$(tr -d '[:space:]' < /etc/modules-load.d/networkprotection.conf)" == "xt_geoip" ]]; then
    rm -f /etc/modules-load.d/networkprotection.conf
fi

systemctl daemon-reload
systemctl enable --now networkprotection.timer

echo "Installiert. Erster automatischer Lauf erfolgt etwa zwei Minuten nach dem Start des Timers."
echo "Für einen kontrollierten Soforttest: systemctl start networkprotection.service"
