#!/usr/bin/env bash

set -u

command_name="$(basename -- "$0")"
printf '%s %s\n' "$command_name" "$*" >> "$MOCK_FIREWALL_LOG"

if [[ "$command_name" == "ipset" && "${1:-}" == "restore" ]]; then
    while IFS= read -r restore_line; do
        printf 'restore %s\n' "$restore_line" >> "$MOCK_FIREWALL_LOG"
    done
fi

if [[ "$command_name" == "ipset" &&
    "${MOCK_FAIL_IPV6_SWAP:-no}" == "yes" &&
    "$*" == "swap networkprotection_asn_v6 networkprotection_asn_v6_new" ]]; then
    exit 1
fi

for argument in "$@"; do
    if [[ "$argument" == "-C" ]]; then
        exit 1
    fi
done

exit 0
