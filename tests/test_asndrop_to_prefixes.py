#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import ipaddress
import json
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


PROJECT_DIR = Path(__file__).resolve().parent.parent


def load_converter() -> ModuleType:
    module_path = PROJECT_DIR / "asndrop_to_prefixes.py"
    spec = importlib.util.spec_from_file_location("asndrop_to_prefixes", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("ASN-DROP-Konverter konnte nicht geladen werden")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONVERTER = load_converter()


class ParseAsnsTest(unittest.TestCase):
    def write_json_lines(self, records: list[dict[str, object]]) -> Path:
        temporary_file = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        self.addCleanup(Path(temporary_file.name).unlink, missing_ok=True)
        with temporary_file:
            for record in records:
                temporary_file.write(json.dumps(record) + "\n")
        return Path(temporary_file.name)

    def test_parses_records_and_metadata(self) -> None:
        input_path = self.write_json_lines(
            [
                {"asn": 64501},
                {"asn": 64500},
                {"type": "metadata", "records": 2},
            ]
        )

        self.assertEqual(CONVERTER.parse_asns(input_path, 2), [64500, 64501])

    def test_rejects_metadata_mismatch(self) -> None:
        input_path = self.write_json_lines(
            [{"asn": 64500}, {"type": "metadata", "records": 2}]
        )

        with self.assertRaisesRegex(CONVERTER.AsnDropError, "Metadaten"):
            CONVERTER.parse_asns(input_path, 1)

    def test_rejects_duplicate_asn(self) -> None:
        input_path = self.write_json_lines([{"asn": 64500}, {"asn": 64500}])

        with self.assertRaisesRegex(CONVERTER.AsnDropError, "Doppelte ASN"):
            CONVERTER.parse_asns(input_path, 1)

    def test_rejects_missing_metadata(self) -> None:
        input_path = self.write_json_lines([{"asn": 64500}])

        with self.assertRaisesRegex(CONVERTER.AsnDropError, "keinen Metadatensatz"):
            CONVERTER.parse_asns(input_path, 1)


class PrefixExtractionTest(unittest.TestCase):
    def payload(self, asn: int, prefixes: list[str]) -> dict[str, object]:
        return {
            "status": "ok",
            "status_code": 200,
            "data_call_status": "supported",
            "data": {
                "resource": str(asn),
                "prefixes": [{"prefix": prefix} for prefix in prefixes],
            },
        }

    def test_separates_valid_ipv4_and_ipv6_prefixes(self) -> None:
        ipv4, ipv6 = CONVERTER.extract_prefixes(
            self.payload(64500, ["8.8.8.0/24", "2001:4860::/48"]),
            64500,
        )

        self.assertEqual(ipv4, {ipaddress.ip_network("8.8.8.0/24")})
        self.assertEqual(ipv6, {ipaddress.ip_network("2001:4860::/48")})

    def test_rejects_non_public_prefix(self) -> None:
        with self.assertRaisesRegex(CONVERTER.AsnDropError, "nicht öffentliches"):
            CONVERTER.extract_prefixes(self.payload(64500, ["10.0.0.0/8"]), 64500)

    def test_rejects_wrong_resource(self) -> None:
        with self.assertRaisesRegex(CONVERTER.AsnDropError, "unerwarteten Ressource"):
            CONVERTER.extract_prefixes(self.payload(64501, []), 64500)


class ResolveAsnsTest(unittest.TestCase):
    def test_collapses_and_deduplicates_networks(self) -> None:
        responses = {
            64500: (
                {
                    ipaddress.ip_network("8.8.8.0/25"),
                    ipaddress.ip_network("8.8.8.128/25"),
                },
                {ipaddress.ip_network("2001:4860::/48")},
            ),
            64501: (
                {ipaddress.ip_network("8.8.8.0/24")},
                {ipaddress.ip_network("2001:4860::/48")},
            ),
        }

        ipv4, ipv6 = CONVERTER.resolve_asns(
            [64500, 64501], lambda asn: responses[asn], workers=2
        )

        self.assertEqual(ipv4, [ipaddress.ip_network("8.8.8.0/24")])
        self.assertEqual(ipv6, [ipaddress.ip_network("2001:4860::/48")])


if __name__ == "__main__":
    unittest.main()
