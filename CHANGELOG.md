# Changelog

All notable changes are documented here. The project follows Semantic
Versioning and uses Git tags in the form `vMAJOR.MINOR.PATCH`.

## [1.0.0] - 2026-09-02

- Add an IPv4/IPv6 address and CIDR whitelist that bypasses the managed GeoIP,
  bad-IP, and ASN-DROP rules without bypassing other firewall rules.
- Add upgrade-safe Debian packaging for existing script-based installations.
- Add GitHub Actions tests, versioned `.deb` artifacts, and tagged releases.
