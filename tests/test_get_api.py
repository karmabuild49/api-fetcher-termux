import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SCRIPT = Path(__file__).resolve().parents[1] / "get_api.py"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        if self.path == "/slow":
            time.sleep(0.2)

        code = 400 if self.path == "/error" else 200

        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.end_headers()
            return

        if self.path == "/cross":
            self.send_response(302)
            self.send_header(
                "Location", self.server.other_url + "/ok"
            )
            self.end_headers()
            return

        self.send_response(code)
        self.send_header(
            "Content-Type", "application/json; charset=utf-8"
        )
        self.end_headers()

        try:
            self.wfile.write(
                json.dumps({
                    "ok": code == 200,
                    "auth": self.headers.get("Authorization"),
                    "accept": self.headers.get("Accept"),
                }).encode()
            )
        except BrokenPipeError:
            pass

    def do_POST(self):
        body = self.rfile.read(
            int(self.headers.get("Content-Length", 0))
        )
        self.send_response(200)
        self.end_headers()
        self.wfile.write(body)

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()


class CLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = [
            ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            for _ in range(2)
        ]
        cls.url = (
            "http://127.0.0.1:"
            + str(cls.servers[0].server_port)
        )
        cls.servers[0].other_url = (
            "http://127.0.0.1:"
            + str(cls.servers[1].server_port)
        )

        for server in cls.servers:
            threading.Thread(
                target=server.serve_forever, daemon=True
            ).start()

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers:
            server.shutdown()
            server.server_close()

    def run_cli(self, *args, env=None):
        return subprocess.run(
            [sys.executable, str(SCRIPT), *args],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )

    def test_get_headers_status(self):
        result = self.run_cli(
            self.url,
            "--status",
            "--response-headers",
            "-H",
            "accept: text/plain",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            json.loads(result.stdout)["accept"], "text/plain"
        )
        self.assertIn("HTTP 200", result.stderr)

    def test_post_and_file(self):
        for args in [
            ("--data", '{"x":1}'),
            ("--data", ""),
        ]:
            result = self.run_cli(self.url, "--raw", *args)
            self.assertEqual(
                result.returncode, 0, result.stderr
            )
            self.assertEqual(result.stdout.strip(), args[1])

        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "in.json"
            source.write_text('{"x":2}')
            result = self.run_cli(
                self.url, "--data-file", str(source)
            )
            self.assertEqual(
                json.loads(result.stdout), {"x": 2}
            )

    def test_save_success_and_error(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "sub" / "out.json"

            for endpoint, code in [
                ("/ok", 0),
                ("/error", 1),
            ]:
                result = self.run_cli(
                    self.url + endpoint,
                    "-o",
                    str(target),
                )
                self.assertEqual(
                    result.returncode, code, result.stderr
                )
                self.assertEqual(
                    json.loads(target.read_text())["ok"],
                    code == 0,
                )

    def test_redirects(self):
        self.assertEqual(
            self.run_cli(self.url + "/redirect").returncode,
            0,
        )

        result = self.run_cli(
            self.url + "/redirect", "--no-redirect"
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("HTTP 302", result.stderr)

        result = self.run_cli(
            self.url + "/cross",
            "-H",
            "Authorization: Bearer test",
        )
        self.assertIsNone(json.loads(result.stdout)["auth"])

    def test_head_and_timeout(self):
        result = self.run_cli(self.url, "-X", "HEAD")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

        result = self.run_cli(
            self.url + "/slow", "--timeout", ".02"
        )
        self.assertEqual(result.returncode, 1)
        self.assertNotIn("Traceback", result.stderr)

    def test_invalid_arguments(self):
        cases = [
            [],
            ["http://["],
            ["http://host:bad"],
            ["http://:80"],
            ["file:///tmp/x"],
            ["http://a b"],
            [self.url, "--timeout", "nan"],
            [self.url, "--timeout", "inf"],
            [self.url, "-H", "Bad Header: x"],
            [self.url, "-H", "X: a\r\nb"],
            [
                self.url,
                "--data",
                "x",
                "--data-file",
                "x",
            ],
            [
                self.url,
                "--data-file",
                "/missing-file",
            ],
        ]

        for args in cases:
            with self.subTest(args=args):
                result = self.run_cli(*args)
                self.assertEqual(
                    result.returncode, 2, result.stderr
                )
                self.assertNotIn("Traceback", result.stderr)

    def test_token_and_unwritable_output(self):
        env = dict(os.environ, TEST_API_TOKEN="abc")
        result = self.run_cli(
            self.url,
            "--token-env",
            "TEST_API_TOKEN",
            env=env,
        )
        self.assertEqual(
            json.loads(result.stdout)["auth"], "Bearer abc"
        )

        env["TEST_API_TOKEN"] = "bad\nvalue"
        self.assertEqual(
            self.run_cli(
                self.url,
                "--token-env",
                "TEST_API_TOKEN",
                env=env,
            ).returncode,
            2,
        )

        with tempfile.TemporaryDirectory() as folder:
            result = self.run_cli(
                self.url, "-o", folder
            )
            self.assertEqual(result.returncode, 1)


if __name__ == "__main__":
    unittest.main()
