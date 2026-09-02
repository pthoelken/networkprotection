#!/usr/bin/env python3

from __future__ import annotations

import csv
import ipaddress
import sys
from pathlib import Path


def convert(input_path: Path, output_path: Path, countries_value: str) -> int:
    requested = frozenset(country.upper() for country in countries_value.split(","))
    found: set[str] = set()
    networks: set[ipaddress.IPv4Network] = set()

    with input_path.open(newline="", encoding="utf-8") as input_file:
        for line_number, row in enumerate(csv.reader(input_file), start=1):
            if len(row) < 3:
                raise ValueError(f"Ungültige CSV-Zeile {line_number}")
            country = row[2].strip().upper()
            if country not in requested:
                continue

            start = ipaddress.ip_address(row[0].strip())
            end = ipaddress.ip_address(row[1].strip())
            if not isinstance(start, ipaddress.IPv4Address):
                continue
            if not isinstance(end, ipaddress.IPv4Address) or start > end:
                raise ValueError(f"Ungültiger IPv4-Bereich in Zeile {line_number}")

            found.add(country)
            networks.update(ipaddress.summarize_address_range(start, end))

    missing = sorted(requested - found)
    if missing:
        raise ValueError(f"Keine IPv4-Daten für Länder: {','.join(missing)}")

    collapsed = ipaddress.collapse_addresses(networks)
    with output_path.open("w", encoding="ascii", newline="\n") as output_file:
        for network in collapsed:
            output_file.write(f"{network}\n")
    return len(found)


def main() -> int:
    if len(sys.argv) != 4:
        print("Aufruf: geoip_to_cidrs.py EINGABE.csv AUSGABE.txt CC,CC", file=sys.stderr)
        return 2
    try:
        convert(Path(sys.argv[1]), Path(sys.argv[2]), sys.argv[3])
    except (OSError, ValueError, csv.Error) as error:
        print(f"GeoIP-Konvertierung fehlgeschlagen: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
