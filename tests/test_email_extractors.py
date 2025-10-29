import unittest
from utils.email_extractors import extract_html_parts_from_stream

CRLF = "\r\n"

class TestEmailExtractors(unittest.TestCase):
    def test_multipart_boundary_html_extraction(self):
        # Construct a simple multipart message with text/plain and text/html
        boundary = "BOUNDARY123"
        msg = (
            f"From: a@example.com{CRLF}"
            f"To: b@example.com{CRLF}"
            f"Subject: Test{CRLF}"
            f"MIME-Version: 1.0{CRLF}"
            f"Content-Type: multipart/alternative; boundary=\"{boundary}\"{CRLF}{CRLF}"
            f"--{boundary}{CRLF}"
            f"Content-Type: text/plain; charset=utf-8{CRLF}{CRLF}"
            f"Hello plain{CRLF}"
            f"--{boundary}{CRLF}"
            f"Content-Type: text/html; charset=utf-8{CRLF}{CRLF}"
            f"<html><body><p>Hello HTML</p></body></html>{CRLF}"
            f"--{boundary}--{CRLF}"
        ).encode("utf-8")
        parts = extract_html_parts_from_stream(msg)
        self.assertTrue(parts, "Should extract at least one HTML part")
        self.assertTrue(any("Hello HTML" in p for p in parts))

    def test_dot_stuffed_and_multi_message_split(self):
        # Two messages concatenated with SMTP end-of-data markers (CRLF . CRLF)
        # First message contains a dot-stuffed HTML line
        msg1 = (
            f"From: x@example.com{CRLF}"
            f"To: y@example.com{CRLF}"
            f"Subject: Dot Stuffed{CRLF}"
            f"Content-Type: text/html; charset=utf-8{CRLF}{CRLF}"
            # Dot-stuffed line would arrive as '..<html>...' which should be unstuffed to '.<html>...'
            f"..<!DOCTYPE html><html><body>Hi A</body></html>{CRLF}"
        ).encode("utf-8")
        msg2 = (
            f"From: x2@example.com{CRLF}"
            f"To: y2@example.com{CRLF}"
            f"Subject: Plain HTML{CRLF}"
            f"Content-Type: text/html; charset=utf-8{CRLF}{CRLF}"
            f"<html><body>Hi B</body></html>{CRLF}"
        ).encode("utf-8")
        stream = msg1 + (CRLF + "." + CRLF).encode("utf-8") + msg2 + (CRLF + "." + CRLF).encode("utf-8")
        parts = extract_html_parts_from_stream(stream)
        # Should capture both HTML bodies (best effort)
        self.assertGreaterEqual(len(parts), 1)
        joined = "\n".join(parts)
        self.assertIn("Hi A", joined)
        self.assertIn("Hi B", joined)

if __name__ == "__main__":
    unittest.main()
