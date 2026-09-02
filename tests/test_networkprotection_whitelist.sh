#!/usr/bin/env bash

set -Eeuo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_DIR
PROJECT_DIR="$(dirname -- "$TEST_DIR")"
readonly PROJECT_DIR

# shellcheck source=networkprotection.sh
source "$PROJECT_DIR/networkprotection.sh"

date() {
    printf '%s\n' "2026-09-02T00:00:00+00:00"
}

test_work_dir="$(mktemp -d /tmp/networkprotection-whitelist-test.XXXXXX)"
readonly test_work_dir
trap 'rm -rf -- "$test_work_dir"' EXIT

mkdir -p "$test_work_dir/bin"
ln -s "$TEST_DIR/fixtures/mock-firewall-command.sh" "$test_work_dir/bin/ipset"
export MOCK_FIREWALL_LOG="$test_work_dir/firewall.log"
PATH="$test_work_dir/bin:$PATH"
export PATH
# Used by update_whitelist_ipsets() from the sourced main script.
# shellcheck disable=SC2034
WORK_DIR="$test_work_dir"
WHITELIST_FILE="$test_work_dir/whitelist.txt"

printf '%s\n' "203.0.113.10" "198.51.100.1/24" "2001:db8::1" > "$WHITELIST_FILE"
update_whitelist_ipsets

grep -Fq \
    "restore add networkprotection_allow_v4_new 198.51.100.0/24 -exist" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "restore add networkprotection_allow_v4_new 203.0.113.10/32 -exist" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "restore add networkprotection_allow_v6_new 2001:db8::1/128 -exist" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ipset swap networkprotection_allow_v4 networkprotection_allow_v4_new" \
    "$MOCK_FIREWALL_LOG"
grep -Fq \
    "ipset swap networkprotection_allow_v6 networkprotection_allow_v6_new" \
    "$MOCK_FIREWALL_LOG"

: > "$MOCK_FIREWALL_LOG"
export MOCK_FAIL_WHITELIST_IPV6_SWAP=yes
if replace_whitelist_ipsets \
    "$test_work_dir/whitelist-ipv4.txt" "$test_work_dir/whitelist-ipv6.txt"; then
    echo "Failed IPv6 whitelist swap was not rejected." >&2
    exit 1
fi
unset MOCK_FAIL_WHITELIST_IPV6_SWAP

v4_swap_count="$(
    grep -Fc \
        "ipset swap networkprotection_allow_v4 networkprotection_allow_v4_new" \
        "$MOCK_FIREWALL_LOG"
)"
[[ "$v4_swap_count" == "2" ]] || {
    echo "IPv4 whitelist was not rolled back after the IPv6 swap failed." >&2
    exit 1
}

echo "Whitelist ipset test successful."
