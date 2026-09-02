#!/usr/bin/env bash

set -Eeuo pipefail

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

readonly NETWORKPROTECTION_VERSION="2026.07.27-6"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
CONFIG_FILE="${NETWORKPROTECTION_CONFIG:-/etc/networkprotection/networkprotection.conf}"
if [[ ! -r "$CONFIG_FILE" ]]; then
    CONFIG_FILE="$SCRIPT_DIR/networkprotection.conf"
fi

# shellcheck disable=SC1090,SC1091
source "$CONFIG_FILE"

: "${ENABLE_IP_BLOCKLIST:=yes}"
: "${ENABLE_GEO_BLOCKLIST:=yes}"
: "${ENABLE_ASN_DROP:=yes}"
: "${BLOCKLIST_URL:=https://lists.blocklist.de/lists/all.txt}"
: "${CUSTOM_LIST_FILE:=/etc/networkprotection/custom-blacklist.txt}"
: "${MIN_BLOCKLIST_ENTRIES:=1000}"
: "${BLOCK_COUNTRIES:=RU,IR,KR,BD}"
: "${IPSET_NAME:=networkprotection_v4}"
: "${GEOIP_SET_NAME:=networkprotection_geo_v4}"
: "${ASN_DROP_V4_SET_NAME:=networkprotection_asn_v4}"
: "${ASN_DROP_V6_SET_NAME:=networkprotection_asn_v6}"
: "${GEOIP_DB_URL:=https://download.db-ip.com/free/dbip-country-lite-$(date +%Y-%m).csv.gz}"
: "${GEOIP_CONVERTER:=$SCRIPT_DIR/geoip_to_cidrs.py}"
: "${ASN_DROP_URL:=https://www.spamhaus.org/drop/asndrop.json}"
: "${RIPESTAT_API_URL:=https://stat.ripe.net/data/announced-prefixes/data.json}"
: "${ASN_DROP_CONVERTER:=$SCRIPT_DIR/asndrop_to_prefixes.py}"
: "${MIN_ASN_DROP_ASNS:=100}"
: "${ASN_DROP_RIPESTAT_WORKERS:=4}"
: "${ASN_DROP_RIPESTAT_TIMEOUT:=30}"
: "${ASN_DROP_RIPESTAT_RETRIES:=3}"
: "${CHAIN_NAME:=NETWORKPROTECTION}"
: "${LOCK_FILE:=/run/networkprotection.lock}"
: "${XTABLES_WAIT_SECONDS:=30}"

readonly TEMP_SET_NAME="${IPSET_NAME}_new"
readonly GEOIP_TEMP_SET_NAME="${GEOIP_SET_NAME}_new"
readonly ASN_DROP_V4_TEMP_SET_NAME="${ASN_DROP_V4_SET_NAME}_new"
readonly ASN_DROP_V6_TEMP_SET_NAME="${ASN_DROP_V6_SET_NAME}_new"
readonly ENTRY_COMMENT="networkprotection: entry"
readonly IP_COMMENT="networkprotection: IPv4 blocklist"
readonly GEO_COMMENT="networkprotection: GeoIP blocklist"
readonly ASN_DROP_V4_COMMENT="networkprotection: Spamhaus ASN-DROP IPv4"
readonly ASN_DROP_V6_COMMENT="networkprotection: Spamhaus ASN-DROP IPv6"

WORK_DIR=""

log() {
    printf '[%s] %s\n' "$(date --iso-8601=seconds)" "$*"
}

warn() {
    printf '[%s] WARNUNG: %s\n' "$(date --iso-8601=seconds)" "$*" >&2
}

die() {
    printf '[%s] FEHLER: %s\n' "$(date --iso-8601=seconds)" "$*" >&2
    exit 1
}

is_enabled() {
    case "$1" in
        1|[Yy][Ee][Ss]|[Tt][Rr][Uu][Ee]|[Oo][Nn]) return 0 ;;
        *) return 1 ;;
    esac
}

cleanup() {
    if [[ -n "$WORK_DIR" && -d "$WORK_DIR" ]]; then
        rm -rf -- "$WORK_DIR"
    fi
}
trap cleanup EXIT

require_root() {
    (( EUID == 0 )) || die "Das Skript muss als root ausgeführt werden."
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "Benötigtes Programm nicht gefunden: $1"
}

validate_config() {
    [[ "$CHAIN_NAME" =~ ^[A-Za-z0-9_.:+-]{1,28}$ ]] || die "Ungültiger CHAIN_NAME: $CHAIN_NAME"
    [[ "$IPSET_NAME" =~ ^[A-Za-z0-9_.:-]{1,27}$ ]] || die "Ungültiger IPSET_NAME: $IPSET_NAME"
    [[ "$GEOIP_SET_NAME" =~ ^[A-Za-z0-9_.:-]{1,27}$ ]] || die "Ungültiger GEOIP_SET_NAME: $GEOIP_SET_NAME"
    [[ "$ASN_DROP_V4_SET_NAME" =~ ^[A-Za-z0-9_.:-]{1,27}$ ]] || \
        die "Ungültiger ASN_DROP_V4_SET_NAME: $ASN_DROP_V4_SET_NAME"
    [[ "$ASN_DROP_V6_SET_NAME" =~ ^[A-Za-z0-9_.:-]{1,27}$ ]] || \
        die "Ungültiger ASN_DROP_V6_SET_NAME: $ASN_DROP_V6_SET_NAME"
    [[ "$IPSET_NAME" != "$GEOIP_SET_NAME" ]] || \
        die "IPSET_NAME und GEOIP_SET_NAME müssen verschieden sein."
    [[ "$IPSET_NAME" != "$ASN_DROP_V4_SET_NAME" ]] || \
        die "IPSET_NAME und ASN_DROP_V4_SET_NAME müssen verschieden sein."
    [[ "$GEOIP_SET_NAME" != "$ASN_DROP_V4_SET_NAME" ]] || \
        die "GEOIP_SET_NAME und ASN_DROP_V4_SET_NAME müssen verschieden sein."
    [[ "$IPSET_NAME" != "$ASN_DROP_V6_SET_NAME" ]] || \
        die "IPSET_NAME und ASN_DROP_V6_SET_NAME müssen verschieden sein."
    [[ "$GEOIP_SET_NAME" != "$ASN_DROP_V6_SET_NAME" ]] || \
        die "GEOIP_SET_NAME und ASN_DROP_V6_SET_NAME müssen verschieden sein."
    [[ "$ASN_DROP_V4_SET_NAME" != "$ASN_DROP_V6_SET_NAME" ]] || \
        die "ASN-DROP-Setnamen müssen verschieden sein."
    [[ "$BLOCK_COUNTRIES" =~ ^[A-Za-z]{2}(,[A-Za-z]{2})*$ ]] || die "Ungültige Länderliste: $BLOCK_COUNTRIES"
    [[ "$MIN_BLOCKLIST_ENTRIES" =~ ^[0-9]+$ ]] || die "MIN_BLOCKLIST_ENTRIES muss numerisch sein."
    [[ "$MIN_ASN_DROP_ASNS" =~ ^[0-9]+$ ]] && (( MIN_ASN_DROP_ASNS > 0 )) || \
        die "MIN_ASN_DROP_ASNS muss eine positive Zahl sein."
    [[ "$ASN_DROP_RIPESTAT_WORKERS" =~ ^[0-9]+$ ]] && \
        (( ASN_DROP_RIPESTAT_WORKERS >= 1 && ASN_DROP_RIPESTAT_WORKERS <= 8 )) || \
        die "ASN_DROP_RIPESTAT_WORKERS muss zwischen 1 und 8 liegen."
    [[ "$ASN_DROP_RIPESTAT_TIMEOUT" =~ ^[0-9]+$ ]] && \
        (( ASN_DROP_RIPESTAT_TIMEOUT > 0 )) || \
        die "ASN_DROP_RIPESTAT_TIMEOUT muss eine positive Zahl sein."
    [[ "$ASN_DROP_RIPESTAT_RETRIES" =~ ^[0-9]+$ ]] && \
        (( ASN_DROP_RIPESTAT_RETRIES > 0 )) || \
        die "ASN_DROP_RIPESTAT_RETRIES muss eine positive Zahl sein."
    [[ "$ASN_DROP_URL" == https://* ]] || die "ASN_DROP_URL muss HTTPS verwenden."
    [[ "$RIPESTAT_API_URL" == https://* ]] || die "RIPESTAT_API_URL muss HTTPS verwenden."
}

replace_ipset_from_file() {
    local set_name="$1"
    local temporary_set_name="$2"
    local input_file="$3"

    # Der Tausch vermeidet ein leeres Schutzfenster während des Imports.
    ipset destroy "$temporary_set_name" 2>/dev/null || true
    ipset create "$temporary_set_name" hash:net family inet hashsize 65536 maxelem 1000000
    if ! awk -v set_name="$temporary_set_name" \
        '{print "add " set_name " " $0 " -exist"}' "$input_file" | ipset restore; then
        ipset destroy "$temporary_set_name" 2>/dev/null || true
        return 1
    fi
    ipset create "$set_name" hash:net family inet hashsize 65536 maxelem 1000000 -exist
    ipset swap "$set_name" "$temporary_set_name"
    ipset destroy "$temporary_set_name"
}

prepare_ipset_from_file() {
    local set_name="$1"
    local family="$2"
    local input_file="$3"

    ipset destroy "$set_name" 2>/dev/null || true
    if ! ipset create "$set_name" hash:net family "$family" \
        hashsize 65536 maxelem 1000000; then
        return 1
    fi
    if ! awk -v set_name="$set_name" \
        '{print "add " set_name " " $0 " -exist"}' "$input_file" | ipset restore; then
        ipset destroy "$set_name" 2>/dev/null || true
        return 1
    fi
}

replace_asn_drop_ipsets() {
    local ipv4_file="$1"
    local ipv6_file="$2"

    if ! prepare_ipset_from_file "$ASN_DROP_V4_TEMP_SET_NAME" inet "$ipv4_file"; then
        return 1
    fi
    if ! prepare_ipset_from_file "$ASN_DROP_V6_TEMP_SET_NAME" inet6 "$ipv6_file"; then
        ipset destroy "$ASN_DROP_V4_TEMP_SET_NAME" 2>/dev/null || true
        return 1
    fi

    if ! ipset create "$ASN_DROP_V4_SET_NAME" hash:net family inet \
        hashsize 65536 maxelem 1000000 -exist ||
        ! ipset create "$ASN_DROP_V6_SET_NAME" hash:net family inet6 \
            hashsize 65536 maxelem 1000000 -exist; then
        ipset destroy "$ASN_DROP_V4_TEMP_SET_NAME" 2>/dev/null || true
        ipset destroy "$ASN_DROP_V6_TEMP_SET_NAME" 2>/dev/null || true
        return 1
    fi

    if ! ipset swap "$ASN_DROP_V4_SET_NAME" "$ASN_DROP_V4_TEMP_SET_NAME"; then
        ipset destroy "$ASN_DROP_V4_TEMP_SET_NAME" 2>/dev/null || true
        ipset destroy "$ASN_DROP_V6_TEMP_SET_NAME" 2>/dev/null || true
        return 1
    fi
    if ! ipset swap "$ASN_DROP_V6_SET_NAME" "$ASN_DROP_V6_TEMP_SET_NAME"; then
        if ! ipset swap "$ASN_DROP_V4_SET_NAME" "$ASN_DROP_V4_TEMP_SET_NAME"; then
            warn "IPv4-ASN-DROP-Set konnte nach dem IPv6-Tauschfehler nicht zurückgesetzt werden."
        fi
        ipset destroy "$ASN_DROP_V4_TEMP_SET_NAME" 2>/dev/null || true
        ipset destroy "$ASN_DROP_V6_TEMP_SET_NAME" 2>/dev/null || true
        return 1
    fi

    ipset destroy "$ASN_DROP_V4_TEMP_SET_NAME"
    ipset destroy "$ASN_DROP_V6_TEMP_SET_NAME"
}

download_file() {
    local url="$1"
    local destination="$2"

    if command -v curl >/dev/null 2>&1; then
        curl --fail --silent --show-error --location \
            --connect-timeout 20 --max-time 180 --retry 3 \
            --output "$destination" "$url"
    elif command -v wget >/dev/null 2>&1; then
        wget --quiet --timeout=20 --tries=3 --output-document="$destination" "$url"
    else
        return 127
    fi
}

normalize_ipv4_lists() {
    local destination="$1"
    shift

    awk '
        function valid_ipv4(value, parts, octets, i, prefix) {
            parts = split(value, cidr, "/")
            if (parts > 2) return 0
            if (parts == 2) {
                prefix = cidr[2]
                if (prefix !~ /^[0-9]+$/ || prefix < 0 || prefix > 32) return 0
            }
            octets = split(cidr[1], ip, ".")
            if (octets != 4) return 0
            for (i = 1; i <= 4; i++) {
                if (ip[i] !~ /^[0-9]+$/ || ip[i] < 0 || ip[i] > 255) return 0
            }
            return 1
        }
        {
            sub(/\r$/, "")
            sub(/[[:space:]]*#.*/, "")
            gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if ($0 != "" && valid_ipv4($0)) print $0
        }
    ' "$@" | LC_ALL=C sort -u > "$destination"
}

update_ipset() {
    local downloaded="$WORK_DIR/downloaded-blocklist.txt"
    local normalized="$WORK_DIR/normalized-blocklist.txt"
    local -a inputs=()
    local entry_count

    log "Lade IPv4-Blockliste von $BLOCKLIST_URL"
    if ! download_file "$BLOCKLIST_URL" "$downloaded"; then
        warn "Download fehlgeschlagen; das aktive IP-Set bleibt unverändert."
        return 1
    fi
    inputs+=("$downloaded")
    if [[ -r "$CUSTOM_LIST_FILE" ]]; then
        inputs+=("$CUSTOM_LIST_FILE")
    else
        warn "Keine lesbare Custom-Liste gefunden: $CUSTOM_LIST_FILE"
    fi

    normalize_ipv4_lists "$normalized" "${inputs[@]}"
    entry_count="$(wc -l < "$normalized")"
    entry_count="${entry_count//[[:space:]]/}"
    if (( entry_count < MIN_BLOCKLIST_ENTRIES )); then
        warn "Nur $entry_count gültige Einträge erhalten (Minimum: $MIN_BLOCKLIST_ENTRIES); \
aktives Set bleibt unverändert."
        return 1
    fi

    replace_ipset_from_file "$IPSET_NAME" "$TEMP_SET_NAME" "$normalized"
    log "IPv4-IP-Set atomar aktualisiert: $entry_count Einträge"
}

ipset_exists() {
    ipset list "$1" >/dev/null 2>&1
}

update_geoip_ipset() {
    local archive="$WORK_DIR/dbip-country-lite.csv.gz"
    local csv_file="$WORK_DIR/dbip-country-lite.csv"
    local networks_file="$WORK_DIR/geoip-networks.txt"
    local entry_count

    [[ -x "$GEOIP_CONVERTER" ]] || { warn "GeoIP-Konverter fehlt: $GEOIP_CONVERTER"; return 1; }
    log "Lade GeoIP-Datenbank von $GEOIP_DB_URL"
    if ! download_file "$GEOIP_DB_URL" "$archive"; then
        warn "GeoIP-Download fehlgeschlagen."
        return 1
    fi
    if ! gzip --decompress --stdout "$archive" > "$csv_file" || [[ ! -s "$csv_file" ]]; then
        warn "GeoIP-Archiv ist ungültig oder leer."
        return 1
    fi
    if ! "$GEOIP_CONVERTER" "$csv_file" "$networks_file" "$BLOCK_COUNTRIES"; then
        warn "GeoIP-Netze konnten nicht erzeugt werden."
        return 1
    fi
    entry_count="$(wc -l < "$networks_file")"
    entry_count="${entry_count//[[:space:]]/}"
    (( entry_count > 0 )) || { warn "Keine GeoIP-Netze für $BLOCK_COUNTRIES erzeugt."; return 1; }

    replace_ipset_from_file "$GEOIP_SET_NAME" "$GEOIP_TEMP_SET_NAME" "$networks_file"
    log "GeoIP-IP-Set atomar aktualisiert: $entry_count Netze für $BLOCK_COUNTRIES"
}

update_asn_drop_ipsets() {
    local asn_drop_file="$WORK_DIR/spamhaus-asndrop.json"
    local ipv4_file="$WORK_DIR/asndrop-ipv4.txt"
    local ipv6_file="$WORK_DIR/asndrop-ipv6.txt"
    local ipv4_count
    local ipv6_count

    [[ -x "$ASN_DROP_CONVERTER" ]] || {
        warn "ASN-DROP-Konverter fehlt: $ASN_DROP_CONVERTER"
        return 1
    }

    log "Lade Spamhaus ASN-DROP-Liste von $ASN_DROP_URL"
    if ! download_file "$ASN_DROP_URL" "$asn_drop_file"; then
        warn "ASN-DROP-Download fehlgeschlagen; aktive ASN-DROP-Sets bleiben unverändert."
        return 1
    fi
    if [[ ! -s "$asn_drop_file" ]]; then
        warn "ASN-DROP-Download ist leer; aktive ASN-DROP-Sets bleiben unverändert."
        return 1
    fi

    log "Löse ASN-DROP-ASNs über RIPEstat in aktuelle BGP-Präfixe auf"
    if ! "$ASN_DROP_CONVERTER" \
        "$asn_drop_file" "$ipv4_file" "$ipv6_file" \
        --api-url "$RIPESTAT_API_URL" \
        --minimum-asns "$MIN_ASN_DROP_ASNS" \
        --workers "$ASN_DROP_RIPESTAT_WORKERS" \
        --timeout "$ASN_DROP_RIPESTAT_TIMEOUT" \
        --retries "$ASN_DROP_RIPESTAT_RETRIES"; then
        warn "ASN-DROP-Präfixe konnten nicht vollständig erzeugt werden."
        return 1
    fi

    ipv4_count="$(wc -l < "$ipv4_file")"
    ipv4_count="${ipv4_count//[[:space:]]/}"
    ipv6_count="$(wc -l < "$ipv6_file")"
    ipv6_count="${ipv6_count//[[:space:]]/}"
    if (( ipv4_count == 0 && ipv6_count == 0 )); then
        warn "RIPEstat lieferte keine ASN-DROP-Präfixe."
        return 1
    fi

    if ! replace_asn_drop_ipsets "$ipv4_file" "$ipv6_file"; then
        warn "ASN-DROP-IP-Sets konnten nicht atomar ausgetauscht werden."
        return 1
    fi
    log "ASN-DROP-IP-Sets atomar aktualisiert: $ipv4_count IPv4- und $ipv6_count IPv6-Präfixe"
}

ipt() {
    iptables -w "$XTABLES_WAIT_SECONDS" "$@"
}

ip6t() {
    ip6tables -w "$XTABLES_WAIT_SECONDS" "$@"
}

configure_managed_chain() {
    local rules_added=0
    local rules_failed=0

    ipt -N "$CHAIN_NAME" 2>/dev/null || true
    # Diese Chain gehört ausschließlich diesem Projekt; keine fremde Chain wird geleert.
    if ! ipt -F "$CHAIN_NAME"; then
        warn "IPv4-Chain $CHAIN_NAME konnte nicht vorbereitet werden."
        return 2
    fi

    if is_enabled "$ENABLE_IP_BLOCKLIST" && ipset list "$IPSET_NAME" >/dev/null 2>&1; then
        if ipt -A "$CHAIN_NAME" -m set --match-set "$IPSET_NAME" src \
            -m comment --comment "$IP_COMMENT" -j DROP; then
            ((rules_added += 1))
        else
            warn "IPv4-Blocklistenregel konnte nicht geladen werden."
            rules_failed=1
        fi
    fi

    if is_enabled "$ENABLE_GEO_BLOCKLIST" && ipset_exists "$GEOIP_SET_NAME"; then
        if ipt -A "$CHAIN_NAME" -m set --match-set "$GEOIP_SET_NAME" src \
            -m comment --comment "$GEO_COMMENT" -j DROP; then
            ((rules_added += 1))
        else
            warn "GeoIP-IP-Set-Regel konnte nicht geladen werden."
            rules_failed=1
        fi
    fi

    if is_enabled "$ENABLE_ASN_DROP" && ipset_exists "$ASN_DROP_V4_SET_NAME"; then
        if ipt -A "$CHAIN_NAME" -m set --match-set "$ASN_DROP_V4_SET_NAME" src \
            -m comment --comment "$ASN_DROP_V4_COMMENT" -j DROP; then
            ((rules_added += 1))
        else
            warn "IPv4-ASN-DROP-Regel konnte nicht geladen werden."
            rules_failed=1
        fi
    fi

    (( rules_failed == 0 )) || return 2
    (( rules_added > 0 )) || return 1
}

configure_managed_ipv6_chain() {
    local rules_added=0

    ip6t -N "$CHAIN_NAME" 2>/dev/null || true
    if ! ip6t -F "$CHAIN_NAME"; then
        warn "IPv6-Chain $CHAIN_NAME konnte nicht vorbereitet werden."
        return 2
    fi

    if is_enabled "$ENABLE_ASN_DROP" && ipset_exists "$ASN_DROP_V6_SET_NAME"; then
        if ip6t -A "$CHAIN_NAME" -m set --match-set "$ASN_DROP_V6_SET_NAME" src \
            -m comment --comment "$ASN_DROP_V6_COMMENT" -j DROP; then
            ((rules_added += 1))
        else
            warn "IPv6-ASN-DROP-Regel konnte nicht geladen werden."
            return 2
        fi
    fi

    (( rules_added > 0 )) || return 1
}

place_entry_rule_first() {
    local table_command="$1"
    local family_label="$2"
    local position

    position="$("$table_command" -L INPUT --line-numbers -n |
        awk -v marker="$ENTRY_COMMENT" \
            '$1 ~ /^[0-9]+$/ && index($0, marker) {print $1; exit}')"
    if [[ "$position" == "1" ]]; then
        log "$family_label-INPUT-Sprung steht bereits an Position 1"
        return 0
    fi

    # Nur der projektspezifische Sprung wird entfernt; Reihenfolge und Inhalt
    # aller fremden Regeln bleiben zueinander unverändert.
    while "$table_command" -C INPUT -m comment --comment "$ENTRY_COMMENT" \
        -j "$CHAIN_NAME" 2>/dev/null; do
        "$table_command" -D INPUT -m comment --comment "$ENTRY_COMMENT" -j "$CHAIN_NAME"
    done
    "$table_command" -I INPUT 1 -m comment --comment "$ENTRY_COMMENT" -j "$CHAIN_NAME"
    log "$family_label-INPUT-Sprung an Position 1 eingesetzt"
}

remove_entry_rule() {
    local table_command="$1"
    local family_label="$2"
    local removed=0

    while "$table_command" -C INPUT -m comment --comment "$ENTRY_COMMENT" \
        -j "$CHAIN_NAME" 2>/dev/null; do
        "$table_command" -D INPUT -m comment --comment "$ENTRY_COMMENT" -j "$CHAIN_NAME"
        removed=1
    done
    if (( removed == 1 )); then
        log "$family_label-INPUT-Sprung entfernt"
    fi
}

main() {
    local configure_ipv4_status=0
    local configure_ipv6_status=0
    local failed=0

    require_root
    log "Network Protection Version $NETWORKPROTECTION_VERSION gestartet"
    require_command awk
    require_command find
    require_command flock
    require_command ipset
    require_command iptables
    require_command ip6tables
    require_command sort
    if is_enabled "$ENABLE_GEO_BLOCKLIST" || is_enabled "$ENABLE_ASN_DROP"; then
        require_command python3
    fi
    if is_enabled "$ENABLE_GEO_BLOCKLIST"; then
        require_command gzip
    fi
    validate_config

    mkdir -p "$(dirname -- "$LOCK_FILE")"
    exec 9>"$LOCK_FILE"
    flock -n 9 || die "Eine weitere Instanz läuft bereits."
    WORK_DIR="$(mktemp -d /tmp/networkprotection.XXXXXX)"

    if is_enabled "$ENABLE_IP_BLOCKLIST"; then
        update_ipset || failed=1
    fi
    if is_enabled "$ENABLE_GEO_BLOCKLIST"; then
        if ! update_geoip_ipset; then
            if ipset_exists "$GEOIP_SET_NAME"; then
                warn "Verwende das vorhandene GeoIP-IP-Set weiter."
            else
                warn "Kein nutzbares GeoIP-IP-Set vorhanden."
                failed=1
            fi
        fi
    fi
    if is_enabled "$ENABLE_ASN_DROP"; then
        if ! update_asn_drop_ipsets; then
            if ipset_exists "$ASN_DROP_V4_SET_NAME" &&
                ipset_exists "$ASN_DROP_V6_SET_NAME"; then
                warn "Verwende die vorhandenen ASN-DROP-IP-Sets weiter."
            else
                warn "Kein vollständiges Paar nutzbarer ASN-DROP-IP-Sets vorhanden."
                failed=1
            fi
        fi
    fi

    configure_managed_chain || configure_ipv4_status=$?
    if (( configure_ipv4_status == 0 )); then
        place_entry_rule_first ipt IPv4
    elif (( configure_ipv4_status == 2 )); then
        # Erfolgreich aufgebaute Regeln müssen auch bei einem Fehler einer
        # weiteren verwalteten Regel erreichbar bleiben.
        place_entry_rule_first ipt IPv4
        warn "Der IPv4-Schutz ist nur teilweise aktiv."
        failed=1
    else
        warn "Keine IPv4-Schutzregel verfügbar; fremde Firewall-Regeln blieben unverändert."
        failed=1
    fi

    configure_managed_ipv6_chain || configure_ipv6_status=$?
    if is_enabled "$ENABLE_ASN_DROP"; then
        if (( configure_ipv6_status == 0 )); then
            place_entry_rule_first ip6t IPv6
        elif (( configure_ipv6_status == 2 )); then
            warn "Der IPv6-ASN-DROP-Schutz ist nicht aktiv."
            failed=1
        else
            warn "Keine IPv6-ASN-DROP-Schutzregel verfügbar."
            failed=1
        fi
    else
        remove_entry_rule ip6t IPv6
    fi

    if (( failed != 0 )); then
        die "Aktualisierung nur teilweise erfolgreich; vorhandener Schutz wurde soweit möglich beibehalten."
    fi
    log "Network Protection erfolgreich aktualisiert"
}

if [[ "${1:-}" == "--version" ]]; then
    printf '%s\n' "$NETWORKPROTECTION_VERSION"
elif [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
