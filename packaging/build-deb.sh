#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PROJECT_DIR
VERSION="$(< "$PROJECT_DIR/VERSION")"
readonly VERSION
readonly DEBIAN_VERSION="1:$VERSION"
readonly OUTPUT_DIR="${OUTPUT_DIR:-$PROJECT_DIR/dist}"

[[ "$VERSION" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] || {
    echo "VERSION is not semantic versioning compatible: $VERSION" >&2
    exit 1
}
if [[ -n "${CI_COMMIT_TAG:-}" && "$CI_COMMIT_TAG" != "v$VERSION" ]]; then
    echo "Git tag $CI_COMMIT_TAG does not match VERSION (expected v$VERSION)." >&2
    exit 1
fi

command -v dpkg-deb >/dev/null 2>&1 || {
    echo "dpkg-deb is required to build the package." >&2
    exit 1
}

BUILD_DIR="$(mktemp -d /tmp/networkprotection-deb.XXXXXX)"
readonly BUILD_DIR
trap 'rm -rf -- "$BUILD_DIR"' EXIT
chmod 0755 "$BUILD_DIR"

install -d -m 0755 \
    "$BUILD_DIR/DEBIAN" \
    "$BUILD_DIR/opt/networkprotection" \
    "$BUILD_DIR/usr/share/networkprotection/defaults" \
    "$BUILD_DIR/lib/systemd/system" \
    "$OUTPUT_DIR"

sed "s/@DEBIAN_VERSION@/$DEBIAN_VERSION/g" \
    "$PROJECT_DIR/packaging/debian/control.in" > "$BUILD_DIR/DEBIAN/control"
install -m 0755 "$PROJECT_DIR/packaging/debian/postinst" "$BUILD_DIR/DEBIAN/postinst"
install -m 0755 "$PROJECT_DIR/packaging/debian/prerm" "$BUILD_DIR/DEBIAN/prerm"
install -m 0755 "$PROJECT_DIR/packaging/debian/postrm" "$BUILD_DIR/DEBIAN/postrm"

install -m 0755 \
    "$PROJECT_DIR/networkprotection.sh" \
    "$PROJECT_DIR/geoip_to_cidrs.py" \
    "$PROJECT_DIR/asndrop_to_prefixes.py" \
    "$PROJECT_DIR/normalize_cidrs.py" \
    "$BUILD_DIR/opt/networkprotection/"
install -m 0644 "$PROJECT_DIR/VERSION" "$BUILD_DIR/opt/networkprotection/VERSION"

install -m 0644 \
    "$PROJECT_DIR/networkprotection.conf" \
    "$PROJECT_DIR/custom-blacklist.txt" \
    "$PROJECT_DIR/whitelist.txt" \
    "$BUILD_DIR/usr/share/networkprotection/defaults/"
install -m 0644 "$PROJECT_DIR/systemd/networkprotection.service" \
    "$BUILD_DIR/lib/systemd/system/networkprotection.service"
install -m 0644 "$PROJECT_DIR/systemd/networkprotection.timer" \
    "$BUILD_DIR/lib/systemd/system/networkprotection.timer"

versioned_package="$OUTPUT_DIR/networkprotection_${VERSION}_all.deb"
stable_package="$OUTPUT_DIR/networkprotection_all.deb"
dpkg-deb --root-owner-group --build "$BUILD_DIR" "$versioned_package"
cp -- "$versioned_package" "$stable_package"

echo "Built $versioned_package"
