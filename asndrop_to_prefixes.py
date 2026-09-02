#!/usr/bin/env python3

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Union


MAX_ASN = 4_294_967_295
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
SOURCE_APP = "networkprotection-asndrop"
USER_AGENT = "NetworkProtection-ASN-DROP/1.0"

IpNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
PrefixFetcher = Callable[[int], tuple[set[ipaddress.IPv4Network], set[ipaddress.IPv6Network]]]


class AsnDropError(ValueError):
    pass


def parse_asns(input_path: Path, minimum_asns: int) -> list[int]:
    asns: list[int] = []
    seen: set[int] = set()
    metadata_records: int | None = None
    data_records = 0

    with input_path.open(encoding="utf-8") as input_file:
        for line_number, raw_line in enumerate(input_file, start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                raise AsnDropError(
                    f"Ungültiges JSON in ASN-DROP-Zeile {line_number}: {error.msg}"
                ) from error
            if not isinstance(record, dict):
                raise AsnDropError(f"ASN-DROP-Zeile {line_number} ist kein JSON-Objekt")

            if record.get("type") == "metadata":
                records_value = record.get("records")
                if (
                    not isinstance(records_value, int)
                    or isinstance(records_value, bool)
                    or records_value < 0
                ):
                    raise AsnDropError(
                        "ASN-DROP-Metadaten enthalten keine gültige Datensatzanzahl"
                    )
                if metadata_records is not None:
                    raise AsnDropError("ASN-DROP-Datei enthält mehrere Metadatensätze")
                metadata_records = records_value
                continue

            asn_value = record.get("asn")
            if (
                not isinstance(asn_value, int)
                or isinstance(asn_value, bool)
                or not 1 <= asn_value <= MAX_ASN
            ):
                raise AsnDropError(f"Ungültige ASN in ASN-DROP-Zeile {line_number}")
            if asn_value in seen:
                raise AsnDropError(f"Doppelte ASN in ASN-DROP-Datei: AS{asn_value}")

            seen.add(asn_value)
            asns.append(asn_value)
            data_records += 1

    if metadata_records is None:
        raise AsnDropError("ASN-DROP-Datei enthält keinen Metadatensatz")
    if metadata_records != data_records:
        raise AsnDropError(
            "ASN-DROP-Metadaten stimmen nicht mit der Datensatzanzahl überein "
            f"({metadata_records} statt {data_records})"
        )
    if len(asns) < minimum_asns:
        raise AsnDropError(
            f"ASN-DROP-Datei enthält nur {len(asns)} ASNs (Minimum: {minimum_asns})"
        )
    return sorted(asns)


def build_ripestat_url(api_url: str, asn: int) -> str:
    parsed = urllib.parse.urlsplit(api_url)
    if parsed.scheme != "https" or not parsed.netloc:
        raise AsnDropError("RIPEstat-API-URL muss eine gültige HTTPS-URL sein")

    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    query.extend((("resource", f"AS{asn}"), ("sourceapp", SOURCE_APP)))
    return urllib.parse.urlunsplit(
        (parsed.scheme, parsed.netloc, parsed.path, urllib.parse.urlencode(query), parsed.fragment)
    )


def read_json_response(url: str, timeout_seconds: int, retries: int) -> dict[str, Any]:
    request = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": USER_AGENT},
        method="GET",
    )
    last_error: BaseException | None = None

    for attempt in range(1, retries + 1):
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                if len(body) > MAX_RESPONSE_BYTES:
                    raise AsnDropError("RIPEstat-Antwort überschreitet das Größenlimit")
                payload = json.loads(body.decode("utf-8"))
                if not isinstance(payload, dict):
                    raise AsnDropError("RIPEstat-Antwort ist kein JSON-Objekt")
                return payload
        except urllib.error.HTTPError as error:
            last_error = error
            if error.code < 500 and error.code != 429:
                break
        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            UnicodeDecodeError,
            json.JSONDecodeError,
        ) as error:
            last_error = error

        if attempt < retries:
            time.sleep(2 ** (attempt - 1))

    raise AsnDropError(f"RIPEstat-Anfrage fehlgeschlagen: {last_error}") from last_error


def extract_prefixes(
    payload: dict[str, Any], asn: int
) -> tuple[set[ipaddress.IPv4Network], set[ipaddress.IPv6Network]]:
    if payload.get("status") != "ok" or payload.get("status_code") != 200:
        raise AsnDropError("RIPEstat meldet keinen erfolgreichen Status")
    if payload.get("data_call_status") != "supported":
        raise AsnDropError("RIPEstat-Endpunkt ist nicht als unterstützt markiert")

    data = payload.get("data")
    if not isinstance(data, dict):
        raise AsnDropError("RIPEstat-Antwort enthält kein gültiges data-Objekt")

    resource = str(data.get("resource", "")).upper().removeprefix("AS")
    if resource != str(asn):
        raise AsnDropError(
            f"RIPEstat-Antwort gehört zu einer unerwarteten Ressource: {resource or 'leer'}"
        )

    prefix_records = data.get("prefixes")
    if not isinstance(prefix_records, list):
        raise AsnDropError("RIPEstat-Antwort enthält keine gültige Präfixliste")

    ipv4_networks: set[ipaddress.IPv4Network] = set()
    ipv6_networks: set[ipaddress.IPv6Network] = set()
    for record in prefix_records:
        if not isinstance(record, dict) or not isinstance(record.get("prefix"), str):
            raise AsnDropError(f"RIPEstat liefert für AS{asn} einen ungültigen Präfixdatensatz")
        try:
            network = ipaddress.ip_network(record["prefix"], strict=True)
        except ValueError as error:
            raise AsnDropError(
                f"RIPEstat liefert für AS{asn} ein ungültiges Präfix: {record['prefix']}"
            ) from error

        if network.prefixlen == 0 or not network.is_global:
            raise AsnDropError(
                f"RIPEstat liefert für AS{asn} ein nicht öffentliches Präfix: {network}"
            )
        if isinstance(network, ipaddress.IPv4Network):
            ipv4_networks.add(network)
        else:
            ipv6_networks.add(network)

    return ipv4_networks, ipv6_networks


def fetch_asn_prefixes(
    api_url: str, asn: int, timeout_seconds: int, retries: int
) -> tuple[set[ipaddress.IPv4Network], set[ipaddress.IPv6Network]]:
    payload = read_json_response(
        build_ripestat_url(api_url, asn),
        timeout_seconds=timeout_seconds,
        retries=retries,
    )
    return extract_prefixes(payload, asn)


def resolve_asns(
    asns: Iterable[int], fetcher: PrefixFetcher, workers: int
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    asn_list = list(asns)
    ipv4_networks: set[ipaddress.IPv4Network] = set()
    ipv6_networks: set[ipaddress.IPv6Network] = set()
    completed = 0

    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ripestat") as executor:
        futures: dict[
            Future[tuple[set[ipaddress.IPv4Network], set[ipaddress.IPv6Network]]], int
        ] = {executor.submit(fetcher, asn): asn for asn in asn_list}
        for future in as_completed(futures):
            asn = futures[future]
            try:
                result_v4, result_v6 = future.result()
            except Exception as error:
                for pending_future in futures:
                    pending_future.cancel()
                raise AsnDropError(
                    f"RIPEstat-Auflösung für AS{asn} fehlgeschlagen: {error}"
                ) from error

            ipv4_networks.update(result_v4)
            ipv6_networks.update(result_v6)
            completed += 1
            if completed % 25 == 0 or completed == len(asn_list):
                print(
                    f"RIPEstat: {completed}/{len(asn_list)} ASNs aufgelöst",
                    file=sys.stderr,
                    flush=True,
                )

    collapsed_v4 = list(ipaddress.collapse_addresses(ipv4_networks))
    collapsed_v6 = list(ipaddress.collapse_addresses(ipv6_networks))
    if not collapsed_v4 and not collapsed_v6:
        raise AsnDropError("RIPEstat lieferte für die ASN-DROP-Liste keine Präfixe")
    return collapsed_v4, collapsed_v6


def write_networks(output_path: Path, networks: Iterable[IpNetwork]) -> None:
    with output_path.open("w", encoding="ascii", newline="\n") as output_file:
        for network in networks:
            output_file.write(f"{network}\n")


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Spamhaus ASN-DROP über RIPEstat in IPv4-/IPv6-Präfixlisten umwandeln"
    )
    parser.add_argument("input", type=Path, help="Spamhaus ASN-DROP JSON Lines")
    parser.add_argument("ipv4_output", type=Path, help="Ausgabedatei für IPv4-Präfixe")
    parser.add_argument("ipv6_output", type=Path, help="Ausgabedatei für IPv6-Präfixe")
    parser.add_argument("--api-url", required=True, help="RIPEstat announced-prefixes Endpoint")
    parser.add_argument("--minimum-asns", type=int, default=100)
    parser.add_argument("--workers", type=int, choices=range(1, 9), default=4)
    parser.add_argument("--timeout", type=int, default=30)
    parser.add_argument("--retries", type=int, default=3)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    if arguments.minimum_asns < 1 or arguments.timeout < 1 or arguments.retries < 1:
        print("ASN-DROP-Konfiguration enthält ungültige Zahlenwerte.", file=sys.stderr)
        return 2

    try:
        asns = parse_asns(arguments.input, arguments.minimum_asns)
        print(f"Spamhaus ASN-DROP: {len(asns)} ASNs geladen", file=sys.stderr)
        ipv4_networks, ipv6_networks = resolve_asns(
            asns,
            lambda asn: fetch_asn_prefixes(
                arguments.api_url,
                asn,
                timeout_seconds=arguments.timeout,
                retries=arguments.retries,
            ),
            arguments.workers,
        )
        write_networks(arguments.ipv4_output, ipv4_networks)
        write_networks(arguments.ipv6_output, ipv6_networks)
    except (AsnDropError, OSError) as error:
        print(f"ASN-DROP-Konvertierung fehlgeschlagen: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
