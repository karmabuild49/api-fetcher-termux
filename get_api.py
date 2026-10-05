#!/usr/bin/env python3
"""Termux-friendly HTTP/API client using Python's standard library."""

import argparse
import json
import math
import os
import re
import socket
import sys
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener

VERSION = "2.0.1"
DEFAULT_USER_AGENT = (
    f"api-collected/{VERSION} "
    f"Python/{sys.version_info.major}.{sys.version_info.minor}"
)


class SafeRedirectHandler(HTTPRedirectHandler):
    """Avoid forwarding credentials to a different origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        redirected = super().redirect_request(
            req, fp, code, msg, headers, newurl
        )
        if redirected is not None:
            old = urlparse(req.full_url)
            new = urlparse(redirected.full_url)

            def origin(url):
                return (
                    url.scheme.lower(),
                    url.hostname,
                    url.port or (443 if url.scheme == "https" else 80),
                )

            if origin(old) != origin(new):
                for name in list(redirected.headers):
                    if name.lower() in (
                        "authorization",
                        "cookie",
                        "proxy-authorization",
                    ):
                        del redirected.headers[name]

        return redirected


class NoRedirectHandler(HTTPRedirectHandler):
    """Prevent automatic redirects."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def parse_headers(values, parser):
    headers = {
        "Accept": "application/json",
        "User-Agent": DEFAULT_USER_AGENT,
    }

    for item in values:
        name, separator, value = item.partition(":")
        name = name.strip()
        value = value.strip()

        if (
            not separator
            or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name)
            or "\r" in item
            or "\n" in item
        ):
            parser.error(
                "Invalid header; expected NAME: VALUE without line breaks"
            )

        for existing in list(headers):
            if existing.lower() == name.lower():
                del headers[existing]

        headers[name] = value

    return headers


def validate_url(url, parser):
    try:
        parsed = urlparse(url)

        if parsed.scheme not in ("http", "https"):
            parser.error("URL must start with http:// or https://")

        if not parsed.hostname:
            parser.error("Invalid URL: hostname is missing")

        parsed.port  # Validate port syntax and range.

        if parsed.username is not None or parsed.password is not None:
            parser.error(
                "Use headers or --token-env instead of URL credentials"
            )

        if any(
            char.isspace() or ord(char) < 32 or ord(char) == 127
            for char in url
        ):
            parser.error(
                "URL contains whitespace or control characters; "
                "percent-encode them"
            )

        url.encode("ascii")

    except (ValueError, UnicodeError):
        parser.error(
            "Invalid URL: check hostname, port, and percent-encoding"
        )

    return url


def prepare_body(args, parser):
    if args.data is not None and args.data_file is not None:
        parser.error("--data and --data-file cannot be used together")

    if args.data_file is not None:
        path = Path(args.data_file)

        if not path.is_file():
            parser.error(f"Data file does not exist: {path}")

        try:
            return path.read_bytes()
        except OSError as error:
            parser.error(f"Could not read {path}: {error}")

    if args.data is not None:
        return args.data.encode("utf-8")

    return None


def decode_body(raw, content_type=""):
    charset = "utf-8"

    if "charset=" in content_type.lower():
        try:
            charset = content_type.lower().split("charset=", 1)[1]
            charset = charset.split(";", 1)[0]
            charset = charset.strip().strip('"')
        except (IndexError, AttributeError):
            charset = "utf-8"

    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def format_body(text):
    if not text:
        return ""

    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return text

    return json.dumps(obj, indent=2, ensure_ascii=False)


def print_headers(headers, stream=sys.stderr):
    for name, value in headers.items():
        print(f"{name}: {value}", file=stream)


def save_output(filename, content):
    path = Path(filename)

    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    except OSError as error:
        print(
            f"[!] Could not write output file: {error}",
            file=sys.stderr,
        )
        return False

    print(f"[+] Saved response to: {path}", file=sys.stderr)
    return True


def build_parser():
    parser = argparse.ArgumentParser(
        prog="get_api.py",
        description=(
            "Fetch HTTP/API endpoints using only "
            "the Python standard library."
        ),
    )

    parser.add_argument(
        "url", nargs="?", help="HTTP/API endpoint URL"
    )
    parser.add_argument(
        "-X",
        "--method",
        choices=[
            "GET", "POST", "PUT", "PATCH",
            "DELETE", "HEAD", "OPTIONS",
        ],
        help="HTTP method",
    )
    parser.add_argument(
        "-H",
        "--header",
        action="append",
        default=[],
        metavar="NAME: VALUE",
        help="HTTP header; may be supplied multiple times",
    )
    parser.add_argument("-d", "--data", help="Request body")
    parser.add_argument(
        "--data-file", metavar="FILE",
        help="Read request body from FILE",
    )
    parser.add_argument(
        "-o", "--output", metavar="FILE",
        help="Save response body to FILE",
    )
    parser.add_argument(
        "--timeout", type=float, default=30.0,
        help="Request timeout in seconds (default: 30)",
    )
    parser.add_argument(
        "--status", action="store_true",
        help="Show HTTP status",
    )
    parser.add_argument(
        "--response-headers", action="store_true",
        help="Show response headers",
    )
    parser.add_argument(
        "--no-redirect", action="store_true",
        help="Do not automatically follow HTTP redirects",
    )
    parser.add_argument(
        "--raw", action="store_true",
        help="Do not pretty-print JSON",
    )
    parser.add_argument(
        "--token-env", metavar="ENV",
        help="Read bearer token from environment variable ENV",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {VERSION}",
    )

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    if not args.url:
        parser.print_help(sys.stderr)
        return 2

    validate_url(args.url, parser)

    if not math.isfinite(args.timeout) or args.timeout <= 0:
        parser.error("--timeout must be finite and greater than 0")

    headers = parse_headers(args.header, parser)

    if args.token_env:
        token = os.environ.get(args.token_env)

        if not token:
            print(
                f"[!] Environment variable {args.token_env!r} "
                "is not set or empty.",
                file=sys.stderr,
            )
            return 2

        if "\r" in token or "\n" in token:
            parser.error("Bearer token must not contain line breaks")

        for name in list(headers):
            if name.lower() == "authorization":
                del headers[name]

        headers["Authorization"] = f"Bearer {token}"

    body = prepare_body(args, parser)
    method = args.method

    if method is None:
        method = "POST" if body is not None else "GET"

    if body is not None:
        if not any(
            name.lower() == "content-type"
            for name in headers
        ):
            headers["Content-Type"] = "application/json"

    request = Request(
        args.url, data=body, headers=headers, method=method
    )

    if args.no_redirect:
        opener = build_opener(NoRedirectHandler())
    else:
        opener = build_opener(SafeRedirectHandler())

    try:
        with opener.open(
            request, timeout=args.timeout
        ) as response:
            raw = response.read()
            content_type = response.headers.get("Content-Type", "")
            text = decode_body(raw, content_type)
            output = text if args.raw else format_body(text)

            if args.status:
                print(
                    f"HTTP {response.status} {response.reason}",
                    file=sys.stderr,
                )

            if args.response_headers:
                print_headers(response.headers)

            if args.output:
                if not save_output(args.output, output):
                    return 1
            elif output:
                print(output)

            return 0

    except HTTPError as error:
        try:
            raw = error.read()
        except (OSError, ValueError) as read_error:
            print(
                f"Could not read HTTP error body: {read_error}",
                file=sys.stderr,
            )
            raw = b""
        finally:
            error.close()

        content_type = error.headers.get("Content-Type", "")
        text = decode_body(raw, content_type)
        detail = text if args.raw else format_body(text)

        print(
            f"HTTP {error.code} {error.reason}",
            file=sys.stderr,
        )

        if args.response_headers:
            print_headers(error.headers)

        if args.output:
            save_output(args.output, detail)
        elif detail:
            print(detail, file=sys.stderr)

        return 1

    except socket.timeout:
        print(
            f"Request timed out after {args.timeout} seconds.",
            file=sys.stderr,
        )
        return 1

    except URLError as error:
        reason = getattr(error, "reason", error)
        print(f"Request failed: {reason}", file=sys.stderr)
        return 1

    except KeyboardInterrupt:
        print("\nRequest cancelled.", file=sys.stderr)
        return 130

    except Exception as error:
        print(
            f"Unexpected error: {type(error).__name__}: {error}",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
