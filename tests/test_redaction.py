import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scanner import is_sensitive_header, redact_header, request_dump  # noqa: E402


class SensitiveHeaderTest(unittest.TestCase):
    def test_credential_bearing_headers_are_detected(self):
        for name in (
            "Authorization",
            "Proxy-Authorization",
            "Cookie",
            "Set-Cookie",
            "X-Api-Key",
            "X-Auth-Token",
            "X-Amz-Security-Token",
            "Private-Token",
            "X-Session-Id",
            "X-Password",
            "X-Client-Secret",
            "ApiKey",
            "AccessKey",
        ):
            with self.subTest(name=name):
                self.assertTrue(is_sensitive_header(name))

    def test_ordinary_headers_are_left_alone(self):
        for name in (
            "Host",
            "User-Agent",
            "Content-Type",
            "Content-Length",
            "Accept",
            "Accept-Encoding",
            "Connection",
            "X-Request-Id",
            "X-Forwarded-For",
            "Referer",
            "X-Keyboard-Layout",
        ):
            with self.subTest(name=name):
                self.assertFalse(is_sensitive_header(name))

    def test_redact_header_replaces_only_the_value(self):
        self.assertEqual(redact_header("X-Auth-Token", "s3cr3t"), "<redacted>")
        self.assertEqual(redact_header("User-Agent", "probe"), "probe")

    def test_request_dump_does_not_leak_custom_token_headers(self):
        dump = request_dump(
            "https://example.com/index.php",
            {
                "X-Auth-Token": "s3cr3t-token",
                "X-Api-Key": "s3cr3t-key",
                "User-Agent": "probe",
            },
            42,
            "minimal multipart control body",
        )

        self.assertNotIn("s3cr3t-token", dump)
        self.assertNotIn("s3cr3t-key", dump)
        self.assertIn("X-Auth-Token: <redacted>", dump)
        self.assertIn("User-Agent: probe", dump)


if __name__ == "__main__":
    unittest.main()
