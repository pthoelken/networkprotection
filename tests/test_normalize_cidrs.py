#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import ipaddress
import tempfile
import unittest
from pathlib import Path
from types import ModuleType


PROJECT_DIR = Path(__file__).resolve().parent.parent


def load_converter() -> ModuleType:
    module_path = PROJECT_DIR / "normalize_cidrs.py"
    spec = importlib.util.spec_from_file_location("normalize_cidrs", module_path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Whitelist converter could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CONVERTER = load_converter()


class ParseNetworksTest(unittest.TestCase):
    def write_list(self, content: str) -> Path:
        temporary_file = tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", delete=False
        )
        self.addCleanup(Path(temporary_file.name).unlink, missing_ok=True)
        with temporary_file:
            temporary_file.write(content)
        return Path(temporary_file.name)

    def test_accepts_addresses_cidrs_comments_and_collapses(self) -> None:
        source = self.write_list(
            "203.0.113.10 # host\n"
            "198.51.100.1/24\n"
            "198.51.100.0/25\n"
            "2001:db8::1\n"
            "2001:db8:1::/48\n"
        )

        ipv4, ipv6 = CONVERTER.parse_networks(source)

        self.assertEqual(
            ipv4,
            [
                ipaddress.ip_network("198.51.100.0/24"),
                ipaddress.ip_network("203.0.113.10/32"),
            ],
        )
        self.assertEqual(
            ipv6,
            [
                ipaddress.ip_network("2001:db8::1/128"),
                ipaddress.ip_network("2001:db8:1::/48"),
            ],
        )

    def test_rejects_invalid_entry_with_line_number(self) -> None:
        source = self.write_list("203.0.113.10\nnot-an-ip\n")

        with self.assertRaisesRegex(ValueError, "line 2"):
            CONVERTER.parse_networks(source)


if __name__ == "__main__":
    unittest.main()
