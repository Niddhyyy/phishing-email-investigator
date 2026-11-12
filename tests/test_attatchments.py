
import unittest
import sys
from pathlib import Path
from email.message import EmailMessage

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from analyze_email import analyze_attachments


class TestAttachmentAnalysis(unittest.TestCase):

    def test_suspicious_attachment(self):
        msg = EmailMessage()
        msg.set_content("Please check the attached file.")
        msg.add_attachment(
            b"fake executable content",
            maintype="application",
            subtype="octet-stream",
            filename="invoice.exe"
        )

        result = analyze_attachments(msg)

        self.assertEqual(len(result), 1)
        self.assertTrue(result[0]["suspicious"])
        self.assertEqual(result[0]["extension"], ".exe")
        self.assertTrue(result[0]["sha256"])

    def test_safe_extension(self):
        msg = EmailMessage()
        msg.set_content("Here is the document.")
        msg.add_attachment(
            b"fake PDF content",
            maintype="application",
            subtype="pdf",
            filename="document.pdf"
        )

        result = analyze_attachments(msg)

        self.assertEqual(len(result), 1)
        self.assertFalse(result[0]["suspicious"])

    def test_no_attachments(self):
        msg = EmailMessage()
        msg.set_content("This email has no attachments.")

        result = analyze_attachments(msg)

        self.assertEqual(result, [])


if __name__ == "__main__":
    unittest.main()
