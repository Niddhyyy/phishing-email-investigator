
import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from analyze_url import analyze_url


class TestURLAnalyzer(unittest.TestCase):

    def test_ip_address_host(self):
        result = analyze_url("http://192.0.2.10/login")
        self.assertIn(
            "Host is an IP address, not a domain name",
            result["findings"]
        )

    def test_url_shortener(self):
        result = analyze_url("https://bit.ly/example")
        self.assertIn(
            "Uses a known URL shortening service",
            result["findings"]
        )

    def test_punycode_domain(self):
        result = analyze_url("https://xn--example-9d0b.com/login")
        self.assertIn(
            "Hostname contains a punycode label",
            result["findings"]
        )

    def test_suspicious_tld(self):
        result = analyze_url("https://example.xyz/login")
        self.assertIn(
            "Uses a monitored TLD: .xyz",
            result["findings"]
        )

    def test_clean_url(self):
        result = analyze_url("https://www.wikipedia.org/")
        self.assertEqual(result["finding_count"], 0)


if __name__ == "__main__":
    unittest.main()
