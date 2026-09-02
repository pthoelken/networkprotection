#!/usr/bin/env bash

set -Eeuo pipefail

TEST_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
readonly TEST_DIR
PROJECT_DIR="$(dirname -- "$TEST_DIR")"
readonly PROJECT_DIR
output_file="$(mktemp /tmp/networkprotection-geoip-test.XXXXXX)"
readonly output_file
trap 'rm -f -- "$output_file"' EXIT

"$PROJECT_DIR/geoip_to_cidrs.py" \
    "$TEST_DIR/fixtures/dbip-sample.csv" "$output_file" "CN,RU"
diff -u "$TEST_DIR/fixtures/dbip-sample.expected" "$output_file"

if "$PROJECT_DIR/geoip_to_cidrs.py" \
    "$TEST_DIR/fixtures/dbip-sample.csv" "$output_file" "CN,DE" 2>/dev/null; then
    echo "Fehlendes Land wurde nicht abgelehnt." >&2
    exit 1
fi

echo "GeoIP-Konvertertest erfolgreich."
