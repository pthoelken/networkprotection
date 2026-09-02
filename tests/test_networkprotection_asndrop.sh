#!/usr/bin/env bash

set -Eeuo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_DIR
PROJECT_DIR="$(dirname -- "$TEST_DIR")"
readonly PROJECT_DIR

# shellcheck source=networkprotection.sh
source "$PROJECT_DIR/networkprotection.sh"

date() {
    printf '%s\n' "2026-07-27T00:00:00+00:00"
}

test_work_dir="$(mktemp -d /tmp/networkprotection-asndrop-test.XXXXXX)"
readonly test_work_dir
trap 'rm -rf -- "$test_work_dir"' EXIT

mkdir -p "$test_work_dir/bin"
ln -s "$TEST_DIR/fixtures/mock-firewall-command.sh" "$test_work_dir/bin/ipset"
ln -s "$TEST_DIR/fixtures/mock-firewall-command.sh" "$test_work_dir/bin/iptables"
ln -s "$TEST_DIR/fixtures/mock-firewall-command.sh" "$test_work_dir/bin/ip6tables"

export MOCK_FIREWALL_LOG="$test_work_dir/firewall.log"
PATH="$test_work_dir/bin:$PATH"
export PATH

ipv4_file="$test_work_dir/ipv4.txt"
ipv6_file="$test_work_dir/ipv6.txt"
printf '%s\n' "8.8.8.0/24" > "$ipv4_file"
printf '%s\n' "2001:4860::/48" > "$ipv6_file"

validate_config
replace_asn_drop_ipsets "$ipv4_file" "$ipv6_file"

grep -Fq \
    "ipset create networkprotection_asn_v4_new hash:net family inet" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ipset create networkprotection_asn_v6_new hash:net family inet6" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ipset swap networkprotection_asn_v4 networkprotection_asn_v4_new" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ipset swap networkprotection_asn_v6 networkprotection_asn_v6_new" \
    "$MOCK_FIREWALL_LOG"

: > "$MOCK_FIREWALL_LOG"
export MOCK_FAIL_IPV6_SWAP=yes
if replace_asn_drop_ipsets "$ipv4_file" "$ipv6_file"; then
    echo "Fehlgeschlagener IPv6-Tausch wurde nicht abgelehnt." >&2
    exit 1
fi
unset MOCK_FAIL_IPV6_SWAP

v4_swap_count="$(
    grep -Fc \
        "ipset swap networkprotection_asn_v4 networkprotection_asn_v4_new" \
        "$MOCK_FIREWALL_LOG"
)"
[[ "$v4_swap_count" == "2" ]] || {
    echo "IPv4-Set wurde nach dem IPv6-Fehler nicht zurückgetauscht." >&2
    exit 1
}

: > "$MOCK_FIREWALL_LOG"
configure_managed_chain
configure_managed_ipv6_chain
place_entry_rule_first ipt IPv4
place_entry_rule_first ip6t IPv6

grep -Fq \
    "iptables -w 30 -A NETWORKPROTECTION -m set --match-set networkprotection_allow_v4 src -m comment --comment networkprotection: IPv4 whitelist -j RETURN" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ip6tables -w 30 -A NETWORKPROTECTION -m set --match-set networkprotection_allow_v6 src -m comment --comment networkprotection: IPv6 whitelist -j RETURN" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "iptables -w 30 -A NETWORKPROTECTION -m set --match-set networkprotection_asn_v4 src" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ip6tables -w 30 -A NETWORKPROTECTION -m set --match-set networkprotection_asn_v6 src" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "iptables -w 30 -I INPUT 1 -m comment --comment networkprotection: entry -j NETWORKPROTECTION" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ip6tables -w 30 -I INPUT 1 -m comment --comment networkprotection: entry -j NETWORKPROTECTION" \
    "$MOCK_FIREWALL_LOG"

whitelist_rule_line="$(grep -Fn "networkprotection_allow_v4 src" "$MOCK_FIREWALL_LOG" | cut -d: -f1)"
block_rule_line="$(grep -Fn "networkprotection_asn_v4 src" "$MOCK_FIREWALL_LOG" | cut -d: -f1)"
(( whitelist_rule_line < block_rule_line )) || {
    echo "Whitelist-Regel steht nicht vor der ASN-DROP-Regel." >&2
    exit 1
}

echo "ASN-DROP-ipset- und Firewalltest erfolgreich."
