
import unittest
import sys
from pathlib import Path
from email import message_from_string

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from risk_scoring import (
    check_sender_impersonation,
    check_return_path_mismatch,
    check_email_authentication
)


class TestEmailSecurity(unittest.TestCase):

    def test_brand_impersonation(self):
        msg = message_from_string(
            "From: PayPal Support <attacker@example.net>\n\nTest"
        )
        result = check_sender_impersonation(msg)
        self.assertTrue(result)

    def test_legitimate_brand_sender(self):
        msg = message_from_string(
            "From: PayPal Support <support@paypal.com>\n\nTest"
        )
        result = check_sender_impersonation(msg)
        self.assertEqual(result, [])

    def test_return_path_mismatch(self):
        msg = message_from_string(
            "From: User <user@example.com>\n"
            "Return-Path: <attacker@other.com>\n\nTest"
        )
        self.assertTrue(check_return_path_mismatch(msg))

    def test_matching_return_path(self):
        msg = message_from_string(
            "From: User <user@example.com>\n"
            "Return-Path: <bounce@example.com>\n\nTest"
        )
        self.assertFalse(check_return_path_mismatch(msg))

    def test_authentication_failures(self):
        msg = message_from_string(
            "Authentication-Results: mx.example.net; "
            "spf=fail; dkim=fail; dmarc=fail\n\nTest"
        )
        result = check_email_authentication(msg)
        self.assertEqual(len(result), 3)

    def test_authentication_success(self):
        msg = message_from_string(
            "Authentication-Results: mx.example.net; "
            "spf=pass; dkim=pass; dmarc=pass\n\nTest"
        )
        result = check_email_authentication(msg)
        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
