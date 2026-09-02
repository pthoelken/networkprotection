#!/usr/bin/env python3
"""Validate and normalize a mixed IPv4/IPv6 address and CIDR list."""

from __future__ import annotations

import argparse
import ipaddress
import sys
from pathlib import Path
from typing import Union

Network = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


def parse_networks(
    source: Path,
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    ipv4: set[ipaddress.IPv4Network] = set()
    ipv6: set[ipaddress.IPv6Network] = set()

    for line_number, raw_line in enumerate(
        source.read_text(encoding="utf-8").splitlines(), 1
    ):
        value = raw_line.split("#", 1)[0].strip()
        if not value:
            continue
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as error:
            raise ValueError(
                f"line {line_number}: {value!r} is not an IP address or CIDR"
            ) from error
        if isinstance(network, ipaddress.IPv4Network):
            ipv4.add(network)
        else:
            ipv6.add(network)

    return (
        list(ipaddress.collapse_addresses(ipv4)),
        list(ipaddress.collapse_addresses(ipv6)),
    )


def write_networks(destination: Path, networks: list[Network]) -> None:
    content = "".join(f"{network}\n" for network in networks)
    destination.write_text(content, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("ipv4_destination", type=Path)
    parser.add_argument("ipv6_destination", type=Path)
    arguments = parser.parse_args()

    try:
        ipv4, ipv6 = parse_networks(arguments.source)
        write_networks(arguments.ipv4_destination, ipv4)
        write_networks(arguments.ipv6_destination, ipv6)
    except (OSError, ValueError) as error:
        print(f"Whitelist error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
