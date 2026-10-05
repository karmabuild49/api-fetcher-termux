#!/usr/bin/env python3
"""Scan website content — including pages behind logins — for possible secrets.

Authentication options (pick one):
  --login-url + --login-user/--login-pass + optional --login-user-field/--login-pass-field
      Performs a form (application/x-www-form-urlencoded) POST login and keeps
      the session cookies for the whole crawl. CSRF tokens in the login form
      are picked up automatically from hidden inputs.
  --cookie "name1=value1; name2=value2"   # paste a session cookie from your browser
  --cookie-jar cookies.txt                 # Netscape-format cookie file (e.g. curl -c)
  --bearer TOKEN                           # sends "Authorization: Bearer TOKEN"

Only audit systems you own or are authorized to test.
"""

import argparse
import hashlib
import html
import http.cookiejar
import json
import re
import sys
import tempfile
import time
from collections import deque
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import urldefrag, urljoin, urlsplit, parse_qsl, urlencode
from urllib.request import (
    HTTPCookieProcessor,
    HTTPRedirectHandler,
    Request,
    build_opener,
)

MAX_BYTES = 2_000_000

RULES = [
    (
        "GitHub token",
        re.compile(
            r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}"
            r"|github_pat_[A-Za-z0-9_]{30,})\b"
        ),
        "high",
    ),
    (
        "AWS access key ID",
        re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
        "medium",
    ),
    (
        "AWS secret access key assignment",
        re.compile(
            r"""(?ix)
            ["']?
            (?:aws)?_?secret[_-]?access[_-]?key
            ["']?\s*[:=]\s*["']
            (?P<secret>[A-Za-z0-9/+=]{40})
            ["']
            """
        ),
        "high",
    ),
    (
        "Google API key",
        re.compile(r"\bAIza[A-Za-z0-9_-]{35}\b"),
        "medium",
    ),
    (
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        "high",
    ),
    (
        "Stripe key",
        re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{20,}\b"),
        "high",
    ),
    (
        "JWT",
        re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"
        ),
        "medium",
    ),
    (
        "Possible secret assignment",
        re.compile(
            r"""(?ix)
            ["']?
            (?:api[_-]?key|access[_-]?token|auth[_-]?token|
               bearer[_-]?token|client[_-]?secret|
               secret[_-]?key|password|passwd|pwd)
            ["']?\s*[:=]\s*["']
            (?P<secret>[A-Za-z0-9_./+=:@!-]{16,})
            ["']
            """
        ),
        "low",
    ),
    (
        "Private key block",
        re.compile(
            r"-----BEGIN "
            r"(?P<kind>(?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?"
            r"PRIVATE KEY)-----"
            r"[\s\S]{20,}?"
            r"-----END (?P=kind)-----"
        ),
        "high",
    ),
]

PLACEHOLDERS = (
    "your_token", "your-token", "your_api", "your-api", "replace_me",
    "changeme", "example", "placeholder", "dummy", "xxxxxxxx",
    "insert_", "todo", "fixme", "test", "sample",
)

API_ENDPOINT_PATTERNS = [
    # fetch/axios/xhr calls with a string URL
    re.compile(
        r"""(?:fetch|\$\.(?:get|post|ajax)|axios(?:\.\w+)?)\s*\(\s*
        ["'`](?P<url>/[^"'`\\]{2,200}|https?://[^"'`\\]{2,200})["'`]""",
        re.VERBOSE,
    ),
    # baseURL / apiBase style assignments
    re.compile(
        r"""["']?(?:base[_-]?url|api[_-]?base|api[_-]?url|endpoint)["']?
        \s*[:=]\s*["'`](?P<url>/[^"'`\\]{2,200}|https?://[^"'`\\]{2,200})["'`]""",
        re.VERBOSE,
    ),
    # quoted REST/GraphQL-looking paths
    re.compile(
        r"""["'`](?P<url>/(?:api|v\d|rest|graphql|rpc|api/v\d)[^"'`\\]{0,180})["'`]"""
    ),
    # OpenAPI / Swagger style paths defined in specs
    re.compile(r"""["'](?P<url>/[^"'`\s]{2,200})["']\s*:\s*\{""", ),
]

# Well-known API description / config files probed directly per origin.
API_PROBE_PATHS = [
    "/openapi.json", "/openapi.yaml", "/swagger.json", "/swagger/v1/swagger.json",
    "/api-docs", "/api/openapi.json", "/api/swagger.json", "/api/schema",
    "/graphql", "/graphiql", "/rest", "/api", "/api/v1", "/api/v2",
    "/.well-known/openapi.json", "/api/health", "/healthz",
    "/sitemap.xml", "/robots.txt", "/.env", "/config.json",
    "/manifest.json", "/assetlinks.json",
]


def origin(url):
    parts = urlsplit(url)
    if parts.scheme not in ("http", "https"):
        raise ValueError("Only HTTP(S) URLs are supported")
    if not parts.hostname:
        raise ValueError("URL hostname is missing")
    if parts.username is not None or parts.password is not None:
        raise ValueError("Do not put credentials in the URL")
    return (
        parts.scheme.lower(),
        parts.hostname.lower(),
        parts.port or (443 if parts.scheme == "https" else 80),
    )


class SameOriginRedirect(HTTPRedirectHandler):
    def __init__(self, allowed_origin):
        self.allowed_origin = allowed_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if origin(newurl) != self.allowed_origin:
            raise URLError("Redirect outside the selected origin blocked")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Links(HTMLParser):
    """Collect links plus API-ish inline data (fetch of JSON scripts, forms)."""

    def __init__(self):
        super().__init__()
        self.items = []
        self.in_form = False
        self.form_fields = []

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "a" and values.get("href"):
            self.items.append((values["href"], "page"))
        elif tag == "script":
            if values.get("src"):
                self.items.append((values["src"], "asset"))
            if values.get("type") in (None, "", "application/json",
                                       "application/ld+json", "module"):
                self.items.append(("@inline", "inline-js"))
        elif tag == "link" and values.get("href"):
            rel = (values.get("rel") or "").lower()
            if "stylesheet" not in rel and "icon" not in rel:
                self.items.append((values["href"], "page"))
        elif tag == "form":
            self.in_form = True
            self.form_fields = []
            if values.get("action"):
                self.items.append((values["action"], "form"))

    def handle_endtag(self, tag):
        if tag == "form":
            self.in_form = False

    def handle_data(self, data):
        # Buffer inline script bodies via feed(); HTMLParser gives us data,
        # so capture JSON blobs in <script type=application/json>.
        pass


def scan_text(text, source):
    findings = []
    seen = set()

    for label, pattern, confidence in RULES:
        for match in pattern.finditer(text):
            secret = (
                match.group("secret")
                if "secret" in pattern.groupindex
                else match.group(0)
            )
            start = (
                match.start("secret")
                if "secret" in pattern.groupindex
                else match.start()
            )

            lower = secret.lower()
            if any(word in lower for word in PLACEHOLDERS):
                continue
            if len(set(secret)) < 5:
                continue

            fingerprint = hashlib.sha256(
                secret.encode("utf-8")
            ).hexdigest()
            line = text.count("\n", 0, start) + 1
            key = (label, line, fingerprint)
            if key in seen:
                continue
            seen.add(key)

            masked = (
                "[private key redacted]"
                if label == "Private key block"
                else secret[:4] + "…" + secret[-4:]
            )
            identity = hashlib.sha256(
                f"{source}\0{label}\0{fingerprint}".encode()
            ).hexdigest()

            findings.append({
                "id": identity,
                "source": source,
                "line": line,
                "type": label,
                "confidence": confidence,
                "raw_token": secret,
                "masked": masked,
                "fingerprint": fingerprint,
                "status": "possible exposure; not validated",
            })

    return findings


def collect_endpoints(text):
    """Extract candidate API endpoints from JS/JSON/HTML text."""
    found = {}
    for pattern in API_ENDPOINT_PATTERNS:
        for match in pattern.finditer(text):
            url = match.group("url")
            if len(url) < 3 or url.startswith("//"):
                continue
            if any(ext in url for ext in (".png", ".jpg", ".gif", ".svg",
                                          ".woff", ".css", ".ico")):
                continue
            found.setdefault(url, None)
    return list(found)


def build_opener_with_auth(args, allowed):
    """Create an opener carrying the requested authentication state."""
    jar = http.cookiejar.CookieJar()

    if args.cookie:
        for pair in args.cookie.split(";"):
            if "=" not in pair:
                continue
            name, _, value = pair.strip().partition("=")
            # Wrap as a real cookie bound to the target host.
            domain = allowed[1]
            secure = allowed[0] == "https"
            jar.set_cookie(http.cookiejar.Cookie(
                version=0, name=name, value=value,
                port=None, port_specified=False,
                domain=domain, domain_specified=False, domain_initial_dot=False,
                domain_dot=domain, path="/", path_specified=True,
                secure=secure, expires=None, discard=True,
                comment=None, comment_url=None, rest={}, rfc2109=False,
            ))

    if args.cookie_jar:
        jar_file = Path(args.cookie_jar).expanduser()
        if not jar_file.is_file():
            raise ValueError(f"Cookie jar not found: {args.cookie_jar}")
        file_jar = http.cookiejar.MozillaCookieJar(str(jar_file))
        file_jar.load(ignore_discard=True, ignore_expires=True)
        for cookie in file_jar:
            jar.set_cookie(cookie)

    opener = build_opener(
        SameOriginRedirect(allowed),
        HTTPCookieProcessor(jar),
    )

    if args.bearer:
        token = args.bearer
        original_open = opener.open

        def open_with_bearer(fullurl, data=None, timeout=None):
            if not isinstance(fullurl, Request):
                fullurl = Request(fullurl)
            if not fullurl.has_header("Authorization"):
                fullurl.add_header("Authorization", f"Bearer {token}")
            return original_open(fullurl, data, timeout)

        opener.open = open_with_bearer

    return opener, jar


class LoginForm(HTMLParser):
    """Find a login form and its hidden (CSRF) fields."""

    def __init__(self):
        super().__init__()
        self.forms = []  # (action, method, fields)
        self._current = None

    def handle_starttag(self, tag, attrs):
        values = dict(attrs)
        if tag == "form":
            self._current = {
                "action": values.get("action") or "",
                "method": (values.get("method") or "get").lower(),
                "fields": [],
            }
        elif tag == "input" and self._current is not None:
            name = values.get("name")
            if not name:
                return
            self._current["fields"].append((
                name,
                (values.get("type") or "text").lower(),
                values.get("value") or "",
            ))
        elif tag == "button" and self._current is not None:
            name = values.get("name")
            if name:
                self._current["fields"].append((
                    name, "submit", values.get("value") or "",
                ))

    def handle_endtag(self, tag):
        if tag == "form" and self._current is not None:
            self.forms.append(self._current)
            self._current = None


def authenticate(args, opener, jar):
    """Perform a form login and reuse the resulting session cookies."""
    base = urldefrag(args.login_url)[0]
    try:
        if origin(base) != origin(args.url):
            raise ValueError("Login URL must share origin with --url")
    except ValueError:
        raise

    with opener.open(Request(base, headers=UA_HEADERS), timeout=args.timeout) as resp:
        page = resp.read(MAX_BYTES).decode(
            resp.headers.get_content_charset() or "utf-8", errors="replace"
        )
        final_url = resp.geturl()

    parser = LoginForm()
    parser.feed(page)

    candidates = [
        f for f in parser.forms
        if any(t in ("password",) for _, t, _ in f["fields"])
    ] or parser.forms
    if not candidates:
        raise ValueError("No form found on the login page")

    form = candidates[0]
    action = urldefrag(urljoin(final_url, form["action"]))[0]
    payload = {}
    for name, ftype, value in form["fields"]:
        if ftype == "hidden":
            payload[name] = value          # CSRF and friends travel along
        elif ftype == "password":
            payload[name] = args.login_pass
        elif ftype in ("text", "email", "tel"):
            payload.setdefault(args.login_user_field or name, args.login_user)
        else:
            payload.setdefault(name, value)
    payload[args.login_user_field] = args.login_user
    payload[args.login_pass_field] = args.login_pass

    request = Request(
        action,
        data=urlencode(payload).encode("utf-8"),
        headers={**UA_HEADERS, "Content-Type": "application/x-www-form-urlencoded"},
        method="POST" if form["method"] == "post" else "GET",
    )
    with opener.open(request, timeout=args.timeout) as resp:
        resp.read(MAX_BYTES)

    session_cookies = [c.name for c in jar]
    if not session_cookies:
        print("[auth] Warning: no cookies were set after login", file=sys.stderr)
    else:
        print(f"[auth] Session cookies: {', '.join(sorted(set(session_cookies)))}")


UA_HEADERS = {
    "User-Agent": "API-Audit/4.0",
    "Accept": (
        "text/html,application/json,application/javascript,"
        "application/x-yaml,text/plain,*/*"
    ),
}


def fetch(opener, url, args, method="GET", data=None):
    request = Request(url, headers=UA_HEADERS, data=data, method=method)
    with opener.open(request, timeout=args.timeout) as response:
        media = response.headers.get_content_type()
        raw = response.read(MAX_BYTES + 1)
    return response, media, raw


def probe_api_docs(opener, args, allowed, findings, errors, endpoints):
    """Fetch known API description files and harvest endpoints from them."""
    base = f"{allowed[0]}://{allowed[1]}" + (
        f":{allowed[2]}" if allowed[2] not in (80, 443) else ""
    )
    for path in API_PROBE_PATHS:
        url = urljoin(base + "/", path.lstrip("/"))
        try:
            response, media, raw = fetch(opener, url, args)
        except HTTPError as error:
            error.close()
            continue
        except (URLError, OSError):
            continue
        if len(raw) > MAX_BYTES:
            continue
        charset = response.headers.get_content_charset() or "utf-8"
        try:
            text = raw.decode(charset, errors="replace")
        except LookupError:
            text = raw.decode("utf-8", errors="replace")

        findings.extend(scan_text(text, url))

        if path.endswith((".json", ".yaml")) or media in (
            "application/json", "application/x-yaml", "text/yaml",
        ):
            # OpenAPI paths: top-level "paths" object keys.
            try:
                spec = json.loads(text)
                for p in (spec.get("paths") or {}):
                    if isinstance(p, str) and p.startswith("/"):
                        endpoints.setdefault(p, url)
                server = (spec.get("servers") or [{}])[0].get("url")
                if server:
                    endpoints.setdefault(server, url)
            except (ValueError, IndexError, AttributeError):
                pass
        endpoints.update({e: url for e in collect_endpoints(text)})
        print(f"[probe] {url}")


def web_scan(args):
    allowed = origin(args.url)
    opener, jar = build_opener_with_auth(args, allowed)

    if args.login_url:
        authenticate(args, opener, jar)

    queue = deque([(urldefrag(args.url)[0], 0, "page")])
    visited = set()
    findings, errors = [], []
    endpoints = {}
    scanned = 0

    if args.probe:
        probe_errors = []
        probe_api_docs(opener, args, allowed, findings, probe_errors, endpoints)
        errors.extend(probe_errors)

    while queue and len(visited) < args.max_pages:
        url, depth, kind = queue.popleft()
        if url in visited:
            continue
        visited.add(url)

        if len(visited) > 1:
            time.sleep(args.delay)

        try:
            response, media, raw = fetch(opener, url, args)
            allowed_media = {
                "application/json", "application/javascript",
                "application/x-javascript", "application/x-yaml",
                "text/yaml", "application/graphql",
            }
            if not (
                media.startswith("text/")
                or media in allowed_media
                or media.endswith("+json")
            ):
                continue

            if len(raw) > MAX_BYTES:
                errors.append({
                    "source": url,
                    "error": "Response exceeded 2 MB; skipped",
                })
                continue

            charset = response.headers.get_content_charset() or "utf-8"
            try:
                text = raw.decode(charset, errors="replace")
            except LookupError:
                text = raw.decode("utf-8", errors="replace")

            final_url = response.geturl()

            scanned += 1
            findings.extend(scan_text(text, final_url))
            print(f"[scan] {scanned}: {final_url}")

            for endpoint in collect_endpoints(text):
                endpoints.setdefault(endpoint, final_url)

            if media == "text/html" and kind == "page":
                parser = Links()
                parser.feed(text)

                for link, next_kind in parser.items:
                    next_depth = depth + (next_kind in ("page", "inline-js"))
                    if next_depth > args.depth:
                        continue

                    candidate = urldefrag(urljoin(final_url, link))[0]
                    try:
                        if origin(candidate) != allowed:
                            continue
                    except ValueError:
                        continue

                    # Avoid expanding URL query combinations.
                    if urlsplit(candidate).query:
                        continue

                    if (
                        candidate not in visited
                        and len(queue) < args.max_pages * 10
                    ):
                        queue.append((candidate, next_depth, next_kind))

        except HTTPError as error:
            errors.append({
                "source": url,
                "error": f"HTTP {error.code}",
            })
            error.close()
        except (URLError, OSError, ValueError) as error:
            errors.append({
                "source": url,
                "error": type(error).__name__,
            })

    # Try to classify endpoints harvested but not yet fetched.
    for endpoint, found_in in sorted(endpoints.items())[:args.max_endpoints]:
        absolute = endpoint if endpoint.startswith("http") else urljoin(
            urldefrag(args.url)[0], endpoint
        )
        try:
            if origin(absolute) != allowed:
                continue
        except ValueError:
            continue
        if absolute in visited:
            continue
        if len(visited) >= args.max_pages:
            break
        visited.add(absolute)
        time.sleep(args.delay)
        try:
            response, media, raw = fetch(opener, absolute, args)
            if len(raw) > MAX_BYTES or not (
                media.startswith("text/")
                or media.endswith("+json")
                or "json" in media
            ):
                continue
            charset = response.headers.get_content_charset() or "utf-8"
            text = raw.decode(charset, errors="replace")
            scanned += 1
            findings.extend(scan_text(text, response.geturl()))
            print(f"[api] {scanned}: {response.geturl()}")
        except HTTPError as error:
            error.close()
        except (URLError, OSError, ValueError):
            pass

    return args.url, scanned, findings, errors, sorted(endpoints)


def save_reports(target, scanned, findings, errors, endpoints, output):
    folder = Path(output).expanduser()
    folder.mkdir(parents=True, exist_ok=True)

    # TOKEN_VAULT_PATCH
    import os

    # Store full values outside the HTML report directory.
    vault = Path.cwd() / ".token-vault"
    if vault.is_symlink():
        raise ValueError("Token folder must not be a symlink")
    vault.mkdir(mode=0o700, exist_ok=True)
    os.chmod(vault, 0o700)

    if folder.resolve() == vault.resolve() or (
        folder.resolve() in vault.resolve().parents
    ):
        raise ValueError("Report directory must not contain the token vault")

    tokens = {}
    for item in findings:
        secret = item.pop("raw_token", None)
        if secret is None:
            continue
        fingerprint = item["fingerprint"]
        entry = tokens.setdefault(fingerprint, {
            "token": secret,
            "types": [],
            "locations": [],
            "fingerprint": fingerprint,
            "validated": False,
        })
        if item["type"] not in entry["types"]:
            entry["types"].append(item["type"])
        entry["locations"].append({
            "source": item["source"],
            "line": item["line"],
        })

    name = hashlib.sha256(target.encode("utf-8")).hexdigest()[:16]
    token_file = vault / f"{name}.json"
    payload = {
        "target": target,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tokens": list(tokens.values()),
    }

    fd, temporary = tempfile.mkstemp(dir=str(vault))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, indent=2, ensure_ascii=False)
        os.replace(temporary, token_file)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

    print(f"Full tokens saved locally: {token_file}")

    state_file = folder / "history.json"

    previous = {}
    if state_file.is_file():
        try:
            previous = json.loads(
                state_file.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            pass

    old = previous.get(target, {})
    current = {item["id"]: item for item in findings}
    old_ids = set(old)
    current_ids = set(current)

    for item in findings:
        item["change"] = (
            "previously seen"
            if item["id"] in old_ids
            else "new"
        )

    absent = [
        old[key] for key in sorted(old_ids - current_ids)
    ]

    report = {
        "version": "4.0",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "scanned": scanned,
        "finding_count": len(findings),
        "errors": errors,
        "findings": findings,
        "api_endpoints": endpoints,
        "not_seen_this_run": absent,
        "history_note": (
            "Not seen does not prove removal: coverage or "
            "request failures may differ between runs."
        ),
    }

    (folder / "report.json").write_text(
        json.dumps(report, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    columns = [
        "source", "line", "type",
        "confidence", "masked", "change",
    ]
    rows = "".join(
        "<tr>" + "".join(
            "<td>" + html.escape(str(item[column])) + "</td>"
            for column in columns
        ) + "</tr>"
        for item in findings
    )
    headings = "".join(
        "<th>" + html.escape(column) + "</th>"
        for column in columns
    )
    endpoint_rows = "".join(
        f"<tr><td>{html.escape(e)}</td><td>{html.escape(str(s))}</td></tr>"
        for e, s in ((e, endpoints[i]) for i, e in enumerate(endpoints))
    )
    page = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width'>"
        "<title>API Audit Report</title><style>"
        "body{font:16px system-ui;background:#10151c;"
        "color:#e6edf3;padding:24px}"
        "table{border-collapse:collapse;width:100%}"
        "td,th{border:1px solid #445;padding:10px;"
        "text-align:left;overflow-wrap:anywhere}"
        ".table{overflow-x:auto}</style></head><body>"
        "<h1>API Audit Report</h1><p>"
        + html.escape(target)
        + f"</p><p>Scanned: {scanned} · "
        + f"Possible findings: {len(findings)} · "
        + f"API endpoints: {len(endpoints)} · "
        + f"Errors: {len(errors)}</p>"
        "<p>Tokens are masked and were not validated. "
        + "Confidence describes pattern matching, not "
        + "whether a credential works.</p>"
        "<h2>Findings</h2>"
        "<div class='table'><table><tr>"
        + headings + "</tr>" + rows
        + "</table></div>"
        "<h2>API endpoints</h2>"
        "<div class='table'><table><tr><th>endpoint</th>"
        + "<th>discovered in</th></tr>" + endpoint_rows
        + "</table></div></body></html>"
    )
    (folder / "report.html").write_text(page, encoding="utf-8")

    # Keep the last run for this target; store only masked findings.
    previous[target] = current
    state_file.write_text(
        json.dumps(previous, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )

    print(f"\nScanned: {scanned}")
    print(f"Possible findings: {len(findings)}")
    print(f"API endpoints: {len(endpoints)}")
    print(f"Errors: {len(errors)}")
    print(f"JSON: {folder / 'report.json'}")
    print(f"HTML: {folder / 'report.html'}")


def main():
    parser = argparse.ArgumentParser(
        description="Website secret exposure audit (supports login-protected pages)"
    )
    parser.add_argument("command", choices=["scan"])
    parser.add_argument("-u", "--url", required=True)
    parser.add_argument("--output", default="reports")
    parser.add_argument("--max-pages", type=int, default=20)
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--delay", type=float, default=0.5)

    auth = parser.add_argument_group("authentication")
    auth.add_argument("--login-url")
    auth.add_argument("--login-user")
    auth.add_argument("--login-pass")
    auth.add_argument("--login-user-field")
    auth.add_argument("--login-pass-field")
    auth.add_argument("--cookie")
    auth.add_argument("--cookie-jar")
    auth.add_argument("--bearer")

    api = parser.add_argument_group("api discovery")
    api.add_argument("--probe", action="store_true",
                     help="Probe well-known API description/config paths")
    api.add_argument("--max-endpoints", type=int, default=50,
                     help="How many discovered endpoints to fetch (default 50)")

    args = parser.parse_args()

    if not 1 <= args.max_pages <= 500:
        parser.error("--max-pages must be between 1 and 500")
    if not 0 <= args.depth <= 10:
        parser.error("--depth must be between 0 and 10")
    if not 0 < args.timeout <= 120:
        parser.error("--timeout must be between 0 and 120")
    if not 0 <= args.delay <= 60:
        parser.error("--delay must be between 0 and 60")
    if not 0 <= args.max_endpoints <= 500:
        parser.error("--max-endpoints must be between 0 and 500")

    auth_methods = sum(bool(x) for x in (
        args.login_url, args.cookie, args.cookie_jar, args.bearer
    ))
    if auth_methods > 1:
        parser.error("Use only one of --login-url, --cookie, --cookie-jar, --bearer")
    if args.login_url:
        if not args.login_user or not args.login_pass:
            parser.error("--login-url requires --login-user and --login-pass")
        if origin(args.login_url) != origin(args.url):
            parser.error("--login-url must share the origin with --url")

    try:
        result = web_scan(args)
        save_reports(*result, args.output)
        return 1 if result[3] else 0
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nCancelled.")
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
