import contextlib
import io
import json
from email import policy
from email.parser import BytesParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

import scanner


URL = "https://example.test/upload.php"
CF_BLOCK = b"<title>Attention Required! | Cloudflare</title>"


def response(status=200, body=b"ok", **kwargs):
    return scanner.HTTPResult(status_code=status, body=body, **kwargs)


class WafTests(unittest.TestCase):
    def check(self, control, probe, **kwargs):
        with patch.object(scanner, "send_post", side_effect=[control, probe]) as send:
            result = scanner.check_waf_url(URL, URL, 5, True, kwargs.get("headers", {}))
        self.assertIsNone(result["vulnerable"])
        self.assertEqual(result["mode"], "waf")
        return result, send

    def test_payload_structure_and_size(self):
        for shaped in (False, True):
            body = scanner.build_waf_body(shaped)
            message = BytesParser(policy=policy.default).parsebytes(
                f"Content-Type: multipart/form-data; boundary={scanner.WAF_BOUNDARY}\r\n"
                "MIME-Version: 1.0\r\n\r\n".encode()
                + body
            )
            parts = list(message.iter_parts())
            self.assertFalse(message.defects)
            self.assertEqual(len(parts), 6 if shaped else 1)
            self.assertTrue(body.endswith(f"--{scanner.WAF_BOUNDARY}--\r\n".encode()))
            self.assertLess(len(body), 10 * 1024)
            names = [
                part.get_param("name", header="content-disposition") for part in parts
            ]
            if shaped:
                self.assertEqual(
                    names,
                    [
                        "PHP_SESSION_UPLOAD_PROGRESS",
                        "t[]",
                        "t[]",
                        "t[]",
                        "file1",
                        "file2",
                    ],
                )
                self.assertEqual(
                    [len(part.get_payload(decode=True)) for part in parts[-2:]],
                    [4096, 4096],
                )
                self.assertEqual(
                    [part.get_filename() for part in parts[-2:]],
                    ["first.bin", "second.bin"],
                )
            else:
                self.assertEqual(names, ["wafprobe"])
                self.assertEqual(parts[0].get_payload(decode=True), b"benign")

    def test_selective_cloudflare_block(self):
        result, send = self.check(response(), response(403, CF_BLOCK))
        self.assertEqual(result["verdict"], "BLOCKED")
        self.assertIs(result["waf_blocked"], True)
        self.assertEqual(send.call_count, 2)
        self.assertEqual(len(result["probes"]), 1)
        self.assertNotIn("wafprobe0001", result["request"])

    def test_no_block_observed(self):
        for status in (200, 201, 204, 404):
            with self.subTest(status=status):
                result, _ = self.check(response(404), response(status))
                self.assertEqual(result["verdict"], "NOT BLOCKED")
                self.assertIs(result["waf_blocked"], False)

    def test_control_rejection_cannot_prove_selectivity(self):
        for status in (401, 403, 405, 413, 429, 500, 502):
            with self.subTest(status=status):
                result, _ = self.check(response(status), response(403, CF_BLOCK))
                self.assertEqual(result["verdict"], "INCONCLUSIVE")
                self.assertIsNone(result["waf_blocked"])

    def test_ambiguous_probe_is_inconclusive(self):
        for status in (401, 403, 405, 413, 429, 500, 502):
            with self.subTest(status=status):
                result, _ = self.check(response(), response(status))
                self.assertEqual(result["verdict"], "INCONCLUSIVE")
                self.assertIsNone(result["waf_blocked"])

    def test_marker_without_403_is_not_a_block(self):
        result, _ = self.check(response(), response(200, CF_BLOCK))
        self.assertIs(result["waf_blocked"], False)

    def test_redirects_are_not_followed(self):
        for shaped in (False, True):
            with self.subTest(shaped=shaped):
                result, send = self.check(
                    response() if shaped else response(302), response(307)
                )
                self.assertEqual(result["verdict"], "REDIRECT")
                self.assertEqual(send.call_count, 2 if shaped else 1)

    def test_network_errors_and_missing_status(self):
        for shaped in (False, True):
            for failure in (
                scanner.HTTPResult(error="request timed out"),
                scanner.HTTPResult(),
            ):
                with self.subTest(shaped=shaped, error=failure.error):
                    result, send = self.check(
                        response() if shaped else failure, failure
                    )
                    self.assertEqual(result["verdict"], "ERROR")
                    self.assertIsNone(result["waf_blocked"])
                    self.assertEqual(send.call_count, 2 if shaped else 1)

    def test_matching_session_context_and_custom_headers(self):
        for headers in (
            {},
            {"cookie": "PHPSESSID=custom", "Authorization": "Bearer secret"},
        ):
            original = dict(headers)
            result, send = self.check(
                response(), response(403, CF_BLOCK), headers=headers
            )
            first_headers, second_headers = [
                call.args[3] for call in send.call_args_list
            ]
            self.assertEqual(first_headers, second_headers)
            self.assertEqual(headers, original)
            if headers:
                self.assertEqual(first_headers, headers)
                self.assertNotIn("secret", result["request"])
                self.assertNotIn("PHPSESSID=custom", result["request"])
            else:
                self.assertEqual(first_headers["Cookie"], "PHPSESSID=wafprobe0001")

    def test_path_aggregation_requires_every_path_blocked(self):
        for verdicts, expected in (
            (["BLOCKED", "BLOCKED"], "BLOCKED"),
            (["BLOCKED", "INCONCLUSIVE"], "INCONCLUSIVE"),
            (["ERROR", "BLOCKED"], "ERROR"),
            (["BLOCKED", "REDIRECT"], "REDIRECT"),
            (["NOT BLOCKED", "BLOCKED"], "NOT BLOCKED"),
            (["NOT BLOCKED", "INCONCLUSIVE"], "NOT BLOCKED"),
            (["INCONCLUSIVE", "NOT BLOCKED"], "NOT BLOCKED"),
        ):
            with self.subTest(verdicts=verdicts):
                results = [
                    dict(
                        scanner.base_result(URL),
                        mode="waf",
                        verdict=v,
                        waf_blocked=v == "BLOCKED",
                    )
                    for v in verdicts
                ]
                with patch.object(
                    scanner, "check_waf_url", side_effect=results
                ) as check:
                    result = scanner.check_vulnerability(
                        URL, paths=["/a.php", "/b.php"], waf_check=True
                    )
                self.assertEqual(result["verdict"], expected)
                self.assertEqual(
                    [call.args[1] for call in check.call_args_list],
                    ["https://example.test/a.php", "https://example.test/b.php"],
                )

    def test_invalid_url_stays_a_waf_error(self):
        with patch.object(scanner, "send_post") as send:
            result = scanner.check_vulnerability("ftp://example.test", waf_check=True)
        self.assertEqual(result["mode"], "waf")
        self.assertEqual(result["verdict"], "ERROR")
        self.assertIsNone(result["waf_blocked"])
        send.assert_not_called()

    def test_default_mode_still_calls_original_scanner(self):
        expected = scanner.base_result(URL)
        with patch.object(scanner, "check_url", return_value=expected) as check:
            with patch.object(scanner, "check_waf_url") as waf:
                self.assertIs(scanner.check_vulnerability(URL), expected)
        check.assert_called_once()
        waf.assert_not_called()


class WafCliTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.requests = []
        requests = cls.requests

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                requests.append((self.path, dict(self.headers), body))
                shaped = b"PHP_SESSION_UPLOAD_PROGRESS" in body
                status, content = 200, b"ok"
                if self.path == "/blocked" and shaped:
                    status, content = 403, CF_BLOCK
                elif self.path == "/blanket":
                    status, content = 403, CF_BLOCK
                elif self.path == "/other" and shaped:
                    status, content = 403, b"Forbidden"
                elif self.path == "/redirect":
                    status = 302
                self.send_response(status)
                self.send_header("Content-Length", str(len(content)))
                self.send_header("X-Powered-By", "PHP/8.4.27")
                if status == 302:
                    self.send_header("Location", "/blocked")
                self.end_headers()
                self.wfile.write(content)

            def log_message(self, *args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.origin = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.requests.clear()

    def cli(self, *args):
        return subprocess.run(
            [sys.executable, str(Path(scanner.__file__)), "--no-color", *args],
            capture_output=True,
            text=True,
            timeout=20,
        )

    def test_live_verdicts_exit_codes_and_json(self):
        for path, verdict, code in (
            ("blocked", "BLOCKED", 0),
            ("open", "NOT BLOCKED", 1),
            ("blanket", "INCONCLUSIVE", 1),
            ("other", "INCONCLUSIVE", 1),
            ("redirect", "REDIRECT", 1),
        ):
            with self.subTest(path=path), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "results.json"
                self.requests.clear()
                completed = self.cli(
                    "--waf-check", "-u", f"{self.origin}/{path}", "-o", str(output)
                )
                self.assertEqual(completed.returncode, code, completed.stderr)
                self.assertIn(f"[WAF {verdict}]", completed.stdout)
                self.assertNotIn("NOT VULNERABLE", completed.stdout)
                result = json.loads(output.read_text())["results"][0]
                self.assertIsNone(result["vulnerable"])
                self.assertEqual(result["verdict"], verdict)
                self.assertEqual(len(self.requests), 1 if path == "redirect" else 2)
                self.assertTrue(all(len(body) < 10240 for _, _, body in self.requests))
                self.assertTrue(
                    all(
                        headers["Cookie"] == "PHPSESSID=wafprobe0001"
                        for _, headers, _ in self.requests
                    )
                )

    def test_quiet_mode_and_multihost_do_not_build_large_probes(self):
        for paths, exit_code in (
            (["blocked", "blocked"], 0),
            (["blocked", "open"], 1),
            (["blocked", "blanket"], 1),
        ):
            with self.subTest(paths=paths), tempfile.TemporaryDirectory() as directory:
                targets = Path(directory) / "hosts.txt"
                targets.write_text("\n".join(f"{self.origin}/{path}" for path in paths))
                output = Path(directory) / "results.json"
                argv = [
                    "scanner.py",
                    "--waf-check",
                    "-q",
                    "-l",
                    str(targets),
                    "-o",
                    str(output),
                ]
                with (
                    patch.object(sys, "argv", argv),
                    patch.object(
                        scanner,
                        "build_probe_body",
                        side_effect=AssertionError("large probe in WAF mode"),
                    ),
                ):
                    with contextlib.redirect_stdout(io.StringIO()) as stdout:
                        with self.assertRaises(SystemExit) as raised:
                            scanner.main()
                self.assertEqual(raised.exception.code, exit_code)
                self.assertNotIn("[WAF BLOCKED]", stdout.getvalue())
                if exit_code:
                    self.assertIn("[WAF ", stdout.getvalue())
                self.assertEqual(
                    json.loads(output.read_text())["total_results"], len(set(paths))
                )

    def test_legacy_mode_over_real_http(self):
        completed = self.cli("-u", f"{self.origin}/legacy")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertIn("[NOT VULNERABLE]", completed.stdout)
        self.assertIn("FIXED", completed.stdout)
        self.assertEqual(len(self.requests), 2)
        self.assertGreater(len(self.requests[1][2]), 1_000_000)

    def test_custom_cookie_and_credentials_over_real_http(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "results.json"
            completed = self.cli(
                "--waf-check",
                "-u",
                f"{self.origin}/blocked",
                "-v",
                "-H",
                "cookie: PHPSESSID=private",
                "-H",
                "Authorization: Bearer secret",
                "-o",
                str(output),
            )
            evidence = output.read_text()
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(len(self.requests), 2)
        for _, headers, _ in self.requests:
            self.assertEqual(headers["cookie"], "PHPSESSID=private")
            self.assertEqual(headers["Authorization"], "Bearer secret")
        for secret in ("private", "Bearer secret"):
            self.assertNotIn(secret, evidence)
            self.assertNotIn(secret, completed.stdout)

    def test_waf_summary_and_path_file(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = Path(directory) / "paths.txt"
            paths.write_text("/blocked\n/open\n")
            argv = [
                "scanner.py",
                "--waf-check",
                "-u",
                self.origin,
                "--path-file",
                str(paths),
            ]
            with (
                patch.object(sys, "argv", argv),
                contextlib.redirect_stdout(io.StringIO()) as stdout,
            ):
                with self.assertRaises(SystemExit) as raised:
                    scanner.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("Exploit-shaped request blocked: 0", stdout.getvalue())
        self.assertIn("Not blocked: 1", stdout.getvalue())
        self.assertNotIn("Not vulnerable:", stdout.getvalue())
        self.assertEqual(
            [path for path, _, _ in self.requests],
            ["/blocked", "/blocked", "/open", "/open"],
        )

    def test_threaded_mode_prints_blocked_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / "hosts.txt"
            hosts.write_text(f"{self.origin}/blocked\n{self.origin}/open\n")
            completed = self.cli("--waf-check", "-l", str(hosts))
        self.assertEqual(completed.returncode, 1)
        self.assertIn("[WAF BLOCKED]", completed.stdout)
        self.assertIn("[WAF NOT BLOCKED]", completed.stdout)

    def test_unexpected_exception_preserves_mode(self):
        argv = ["scanner.py", "--waf-check", "-u", self.origin]
        with (
            patch.object(sys, "argv", argv),
            patch.object(
                scanner,
                "check_vulnerability",
                side_effect=RuntimeError("unexpected failure"),
            ),
        ):
            with contextlib.redirect_stdout(io.StringIO()) as stdout:
                with self.assertRaises(SystemExit) as raised:
                    scanner.main()
        self.assertEqual(raised.exception.code, 1)
        self.assertIn("[WAF ERROR]", stdout.getvalue())
        self.assertIn("Inconclusive/redirects/errors: 1", stdout.getvalue())

    def test_legacy_summary_and_vulnerable_exit_code(self):
        for vulnerable, verdict in ((True, "VULNERABLE"), (False, "FIXED")):
            with self.subTest(verdict=verdict):
                result = dict(
                    scanner.base_result(self.origin),
                    vulnerable=vulnerable,
                    verdict=verdict,
                )
                with (
                    patch.object(sys, "argv", ["scanner.py", "-u", self.origin]),
                    patch.object(scanner, "check_vulnerability", return_value=result),
                ):
                    with contextlib.redirect_stdout(io.StringIO()) as stdout:
                        with self.assertRaises(SystemExit) as raised:
                            scanner.main()
                self.assertEqual(raised.exception.code, 1 if vulnerable else 0)
                self.assertIn(f"Vulnerable: {int(vulnerable)}", stdout.getvalue())

    def test_quiet_single_host_and_output_failure(self):
        blocked = self.cli("--waf-check", "-q", "-u", f"{self.origin}/blocked")
        self.assertEqual(blocked.returncode, 0)
        self.assertEqual(blocked.stdout, "")
        opened = self.cli("--waf-check", "-q", "-u", f"{self.origin}/open")
        self.assertEqual(opened.returncode, 1)
        self.assertIn("[WAF NOT BLOCKED]", opened.stdout)
        with tempfile.TemporaryDirectory() as directory:
            failed = self.cli(
                "--waf-check", "-u", f"{self.origin}/blocked", "-o", directory
            )
        self.assertEqual(failed.returncode, 2)


if __name__ == "__main__":
    unittest.main()
