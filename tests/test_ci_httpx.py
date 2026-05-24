import json
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
REQUESTS = []


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        REQUESTS.append(
            {
                "method": "GET",
                "path": self.path,
                "host": self.headers.get("Host", ""),
                "user_agent": self.headers.get("User-Agent", ""),
                "body": "",
            }
        )
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/final")
            self.send_header("Server", "cloudflare-test")
            self.end_headers()
            return
        if self.path == "/redirect-external":
            self.send_response(302)
            self.send_header("Location", "http://example.com/final")
            self.send_header("Server", "cloudflare-test")
            self.end_headers()
            return
        if self.path == "/redirect-query?start=1":
            self.send_response(302)
            self.send_header("Location", "?next=1")
            self.send_header("Server", "cloudflare-test")
            self.end_headers()
            return
        if self.path == "/redirect-query?next=1":
            body = (
                b"<html><head><title>Query Redirect Final</title></head>"
                b"<body>query ok</body></html>\n"
            )
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Server", "origin")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/cf-ray":
            body = b"<html><head><title>CDN Header</title></head><body>edge</body></html>\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "origin")
            self.send_header("CF-Ray", "abc123-SYD")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/header-extract":
            body = b"<html><head><title>Header Extract</title></head><body>none</body></html>\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Server", "origin")
            self.send_header("X-Trace-Token", "trace-header-only-12345")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/final":
            body = (
                b"<html><head><title>Final Page</title></head>"
                b'<script src="/static/jquery.min.js"></script>'
                b'<link href="/static/bootstrap.min.css" rel="stylesheet">'
                b"<body>admin test@example.com 192.168.1.1</body></html>\n"
            )
        else:
            body = (
                b"<html><head><title>Home Page</title></head>"
                b'<script src="/static/jquery.min.js"></script>'
                b'<link href="/wp-content/themes/example/style.css" rel="stylesheet">'
                b"<body>hello admin world</body></html>\n"
            )

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "cloudflare-test")
        self.send_header("X-Powered-By", "PHP/8.2")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0") or "0")
        body = self.rfile.read(length)
        REQUESTS.append(
            {
                "method": "POST",
                "path": self.path,
                "host": self.headers.get("Host", ""),
                "user_agent": self.headers.get("User-Agent", ""),
                "body": body.decode("utf-8", errors="replace"),
            }
        )
        response = (
            b"<html><head><title>Post Page</title></head>"
            b"<body>posted:"
            + body
            + b"</body></html>\n"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "origin")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, fmt, *args):
        return


def build_cli():
    subprocess.run(["make", "-C", "httpxlib", "all"], cwd=ROOT, check=True)


def run_cli(*args):
    proc = subprocess.run(
        [str(ROOT / "httpxlib" / "ci-httpx"), *args],
        cwd=ROOT,
        check=True,
        text=True,
        capture_output=True,
    )
    return [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]


def run_cli_raw(*args):
    return subprocess.run(
        [str(ROOT / "httpxlib" / "ci-httpx"), *args],
        cwd=ROOT,
        text=True,
        capture_output=True,
    )


def test_ci_httpx_json_match_filter_redirect_and_extractors():
    build_cli()
    REQUESTS.clear()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port

        filtered = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--filter-code",
            "200",
        )
        assert filtered == []

        matched = run_cli(
            "-j",
            "-u",
            "127.0.0.1",
            "--default-scheme",
            "http",
            "--no-fallback-scheme",
            "-p",
            f"http:{port}",
            "--probe-all-ips",
            "--match-code",
            "200",
            "--match-string",
            "missing,admin",
            "--include-response-header",
        )
        assert len(matched) == 1
        assert matched[0]["status_code"] == 200
        assert isinstance(matched[0]["time"], str)
        assert re.fullmatch(r"[0-9]+(\.[0-9]+)?(ns|us|ms|s)", matched[0]["time"])
        assert matched[0]["title"] == "Home Page"
        assert matched[0]["host_ip"] == "127.0.0.1"
        assert matched[0]["cdn_name"] == "cloudflare"
        assert matched[0]["tech"] == ["Cloudflare", "PHP", "WordPress", "jQuery"]
        assert matched[0]["header"]["Server"] == "cloudflare-test"
        assert any(request["user_agent"] for request in REQUESTS)

        regex_matched = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-regex",
            "hello,admin",
        )
        assert len(regex_matched) == 1
        assert regex_matched[0]["title"] == "Home Page"

        regex_filtered = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--filter-regex",
            "definitely-missing,admin",
        )
        assert regex_filtered == []

        user_agent_count = len(REQUESTS)
        explicit_agent = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "-H",
            "User-Agent: exact-agent",
        )
        assert len(explicit_agent) == 1
        assert explicit_agent[0]["host_ip"] == "127.0.0.1"
        assert REQUESTS[user_agent_count]["user_agent"] == "exact-agent"

        multi_path = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}",
            "--path",
            "/,/final",
            "--match-code",
            "200",
        )
        assert [row["path"] for row in multi_path] == ["/", "/final"]
        assert [row["title"] for row in multi_path] == ["Home Page", "Final Page"]

        multi_target = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/,http://127.0.0.1:{port}/final",
            "--match-code",
            "200",
        )
        assert [row["path"] for row in multi_target] == ["/", "/final"]
        assert [row["title"] for row in multi_target] == ["Home Page", "Final Page"]

        original_path = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/base?keep=1",
            "--match-code",
            "200",
        )
        assert len(original_path) == 1
        assert original_path[0]["path"] == "/base"
        assert REQUESTS[-1]["path"] == "/base?keep=1"

        root_override = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/base?keep=1",
            "--path",
            "/",
            "--match-code",
            "200",
        )
        assert len(root_override) == 1
        assert root_override[0]["path"] == "/"
        assert root_override[0]["url"] == f"http://127.0.0.1:{port}/"
        assert REQUESTS[-1]["path"] == "/"

        query_override = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/base?keep=1",
            "--path",
            "final?next=1",
            "--match-code",
            "200",
        )
        assert len(query_override) == 1
        assert query_override[0]["path"] == "/final"
        assert query_override[0]["url"] == f"http://127.0.0.1:{port}/final?next=1"
        assert REQUESTS[-1]["path"] == "/final?next=1"

        post_rows = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/submit",
            "-x",
            "POST",
            "--body",
            "payload",
            "--include-response",
        )
        assert len(post_rows) == 1
        assert post_rows[0]["method"] == "POST"
        assert post_rows[0]["title"] == "Post Page"
        assert "posted:payload" in post_rows[0]["body"]
        assert REQUESTS[-1]["method"] == "POST"
        assert REQUESTS[-1]["body"] == "payload"

        method_rows = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "-x",
            "GET",
            "-x",
            "POST",
            "--body",
            "multi",
            "--match-code",
            "200",
        )
        assert [row["method"] for row in method_rows] == ["GET", "POST"]
        assert REQUESTS[-2]["method"] == "GET"
        assert REQUESTS[-2]["body"] == ""
        assert REQUESTS[-1]["method"] == "POST"
        assert REQUESTS[-1]["body"] == "multi"

        method_csv_rows = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "-x",
            "GET,POST",
            "--body",
            "csv",
            "--match-code",
            "200",
        )
        assert [row["method"] for row in method_csv_rows] == ["GET", "POST"]
        assert REQUESTS[-2]["method"] == "GET"
        assert REQUESTS[-2]["body"] == ""
        assert REQUESTS[-1]["method"] == "POST"
        assert REQUESTS[-1]["body"] == "csv"

        cdn_header_match = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/cf-ray",
            "--match-cdn",
            "fastly,cloudflare",
        )
        assert len(cdn_header_match) == 1
        assert cdn_header_match[0]["cdn"] is True
        assert cdn_header_match[0]["cdn_name"] == "cloudflare"

        cdn_header_filter = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/cf-ray",
            "-fcdn",
            "fastly,cloudflare",
        )
        assert cdn_header_filter == []

        string_filter_csv = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--filter-string",
            "missing,admin",
        )
        assert string_filter_csv == []

        condition_matched = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-condition",
            'status_code == 200 && title contains "Home"',
        )
        assert len(condition_matched) == 1
        assert condition_matched[0]["title"] == "Home Page"

        condition_filtered = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--filter-condition",
            'cdn == true || status_code == 500',
        )
        assert condition_filtered == []

        invalid_filter_condition = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--filter-condition",
            "missing expression",
        )
        assert invalid_filter_condition.returncode == 2
        assert "invalid option value" in invalid_filter_condition.stderr
        assert invalid_filter_condition.stdout == ""

        invalid_match_condition = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-condition",
            "missing expression",
        )
        assert invalid_match_condition.returncode == 2
        assert "invalid option value" in invalid_match_condition.stderr
        assert invalid_match_condition.stdout == ""

        redirected = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/redirect",
            "--follow-redirects",
            "--include-chain",
            "--include-response",
            "--extract-preset",
            "mail",
            "--extract-preset",
            "ipv4",
            "--extract-regex",
            "Final [A-Za-z]+",
        )
        assert len(redirected) == 1
        result = redirected[0]
        assert result["url"] == f"http://127.0.0.1:{port}/final"
        assert result["final_url"] == f"http://127.0.0.1:{port}/final"
        assert result["port"] == str(port)
        assert result["status_code"] == 200
        assert result["chain_status_codes"] == [302, 200]
        assert result["chain"][0]["status_code"] == 302
        assert result["chain"][0]["request-url"] == f"http://127.0.0.1:{port}/redirect"
        assert "GET /redirect HTTP/" in result["chain"][0]["request"]
        assert "HTTP/1.0 302" in result["chain"][0]["response"]
        assert result["chain"][1]["url"] == f"http://127.0.0.1:{port}/final"
        assert result["chain"][1]["request-url"] == f"http://127.0.0.1:{port}/final"
        assert "GET /final HTTP/" in result["chain"][1]["request"]
        assert "HTTP/1.0 200" in result["chain"][1]["response"]
        assert result["extracts"]["mail"] == ["test@example.com"]
        assert result["extracts"]["ipv4"] == ["192.168.1.1"]
        assert result["extracts"]["Final [A-Za-z]+"] == ["Final Page"]
        assert "body" in result
        assert "request" in result
        assert result["header"]["Server"] == "cloudflare-test"

        extract_regex_keeps_commas = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/final",
            "--extract-regex",
            "Final Page,Nope",
        )
        assert len(extract_regex_keeps_commas) == 1
        assert "extracts" not in extract_regex_keeps_commas[0]

        header_extract = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/header-extract",
            "--extract-regex",
            "trace-header-only-[0-9]+",
        )
        assert len(header_extract) == 1
        assert header_extract[0]["extracts"]["trace-header-only-[0-9]+"] == [
            "trace-header-only-12345"
        ]

        query_redirect = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/redirect-query?start=1",
            "--follow-redirects",
            "--include-chain",
        )
        assert len(query_redirect) == 1
        assert query_redirect[0]["url"] == (
            f"http://127.0.0.1:{port}/redirect-query?next=1"
        )
        assert query_redirect[0]["title"] == "Query Redirect Final"
        assert query_redirect[0]["chain"][1]["request-url"] == (
            f"http://127.0.0.1:{port}/redirect-query?next=1"
        )

        same_host_redirect = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/redirect",
            "--follow-host-redirects",
            "--include-chain",
        )
        assert len(same_host_redirect) == 1
        assert same_host_redirect[0]["url"] == f"http://127.0.0.1:{port}/final"
        assert same_host_redirect[0]["chain_status_codes"] == [302, 200]

        external_redirect = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/redirect-external",
            "--follow-host-redirects",
            "--include-chain",
        )
        assert len(external_redirect) == 1
        assert external_redirect[0]["url"] == (
            f"http://127.0.0.1:{port}/redirect-external"
        )
        assert external_redirect[0]["status_code"] == 302
        assert external_redirect[0]["location"] == "http://example.com/final"
        assert external_redirect[0]["chain_status_codes"] == [302]

        output_path = ROOT / "tests" / ".ci-httpx-output.jsonl"
        try:
            subprocess.run(
                [
                    str(ROOT / "httpxlib" / "ci-httpx"),
                    "-j",
                    "-o",
                    str(output_path),
                    "-u",
                    f"http://127.0.0.1:{port}/",
                    "--match-code",
                    "200",
                ],
                cwd=ROOT,
                check=True,
                text=True,
                capture_output=True,
            )
            rows = [
                json.loads(line)
                for line in output_path.read_text().splitlines()
                if line.strip()
            ]
            assert len(rows) == 1
            assert rows[0]["url"] == f"http://127.0.0.1:{port}/"
        finally:
            output_path.unlink(missing_ok=True)
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_default_custom_port_uses_requested_port_only():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            "127.0.0.1",
            "-p",
            str(port),
            "--timeout",
            "1",
        )
        assert len(rows) == 1
        assert rows[0]["scheme"] == "http"
        assert rows[0]["status_code"] == 200
        assert rows[0]["failed"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_default_scheme_order_uses_explicit_port():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            f"127.0.0.1:{port}",
            "--timeout",
            "1",
        )
        assert len(rows) == 1
        assert rows[0]["url"] == f"http://127.0.0.1:{port}"
        assert rows[0]["path"] == "/"
        assert rows[0]["scheme"] == "http"
        assert rows[0]["status_code"] == 200
        assert rows[0]["failed"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_custom_port_scheme_overrides_input_scheme():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            "https://127.0.0.1",
            "-p",
            f"http:{port}",
            "--match-code",
            "200",
            "--timeout",
            "1",
        )
        assert len(rows) == 1
        assert rows[0]["url"] == f"http://127.0.0.1:{port}/"
        assert rows[0]["scheme"] == "http"
        assert rows[0]["status_code"] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_accepts_httpx_single_dash_aliases():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-json",
            "-target",
            f"http://127.0.0.1:{port}",
            "-path",
            "/final",
            "-sc",
            "-cl",
            "-ct",
            "-location",
            "-lc",
            "-wc",
            "-title",
            "-server",
            "-cdn",
            "-td",
            "-irh",
            "-mc",
            "200",
            "-ms",
            "test@example.com",
            "-er",
            "Final [A-Za-z]+",
            "-ep",
            "mail",
        )
        assert len(rows) == 1
        assert rows[0]["url"] == f"http://127.0.0.1:{port}/final"
        assert rows[0]["status_code"] == 200
        assert rows[0]["content_type"] == "text/html; charset=utf-8"
        assert rows[0]["title"] == "Final Page"
        assert rows[0]["webserver"] == "cloudflare-test"
        assert rows[0]["cdn_name"] == "cloudflare"
        assert rows[0]["tech"] == ["Cloudflare", "PHP", "jQuery", "Bootstrap"]
        assert rows[0]["header"]["Server"] == "cloudflare-test"
        assert rows[0]["extracts"]["mail"] == ["test@example.com"]
        assert rows[0]["extracts"]["Final [A-Za-z]+"] == ["Final Page"]

        preview_display = run_cli(
            "-json",
            "-target",
            f"http://127.0.0.1:{port}/",
            "-bp",
            "-mc",
            "200",
        )
        assert len(preview_display) == 1
        assert preview_display[0]["body_preview"].startswith("<html>")
        assert len(preview_display[0]["body_preview"]) <= 100

        preview_sized = run_cli(
            "-json",
            "-target",
            f"http://127.0.0.1:{port}/",
            "-bp",
            "12",
            "-mc",
            "200",
        )
        assert len(preview_sized) == 1
        assert preview_sized[0]["body_preview"] == "<html><head>"

        preview_long_equals = run_cli(
            "-json",
            "-target",
            f"http://127.0.0.1:{port}/",
            "--body-preview=12",
            "-mc",
            "200",
        )
        assert len(preview_long_equals) == 1
        assert preview_long_equals[0]["body_preview"] == "<html><head>"
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_plain_output_honors_display_flags():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        default = run_cli_raw(
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-code",
            "200",
        )
        assert default.returncode == 0
        assert default.stdout.strip() == f"http://127.0.0.1:{port}/"

        with_fields = run_cli_raw(
            "-u",
            f"http://127.0.0.1:{port}/",
            "-sc",
            "-title",
            "-server",
            "-td",
            "-mc",
            "200",
        )
        assert with_fields.returncode == 0
        assert with_fields.stdout.strip() == (
            f"http://127.0.0.1:{port}/ [200] [Home Page] "
            "[cloudflare-test] [Cloudflare,PHP,WordPress,jQuery]"
        )
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_no_fallback_probes_both_schemes():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            "127.0.0.1",
            "-p",
            f"http:{port},https:{port}",
            "--no-fallback",
            "--timeout",
            "1",
        )
        assert {row["scheme"] for row in rows} == {"http", "https"}
        by_scheme = {row["scheme"]: row for row in rows}
        assert by_scheme["http"]["status_code"] == 200
        assert by_scheme["http"]["failed"] is False
        assert by_scheme["https"]["failed"] is True
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_ports_support_explicit_both_scheme_prefix():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            "127.0.0.1",
            "-p",
            f"http&https:{port}",
            "--timeout",
            "1",
        )
        assert [row["scheme"] for row in rows] == ["https", "http"]
        assert rows[0]["failed"] is True
        assert rows[1]["status_code"] == 200
        assert rows[1]["failed"] is False
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_ports_support_nmap_style_ranges():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            "127.0.0.1",
            "-p",
            f"http:{port - 1}-{port}",
            "--match-code",
            "200",
            "--timeout",
            "1",
        )
        assert len(rows) == 1
        assert rows[0]["url"] == f"http://127.0.0.1:{port}/"
        assert rows[0]["status_code"] == 200
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_ports_dedupe_exact_duplicate_specs():
    build_cli()
    REQUESTS.clear()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            "127.0.0.1",
            "-p",
            f"http:{port},http:{port}",
            "--match-code",
            "200",
        )
        assert len(rows) == 1
        assert len(REQUESTS) == 1
        assert rows[0]["url"] == f"http://127.0.0.1:{port}/"
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_ports_validate_and_preserve_scheme_matching():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            "127.0.0.1",
            "--default-scheme",
            "HTTP",
            "--no-fallback-scheme",
            "-p",
            f"HTTPS:{port}",
            "--match-code",
            "200",
        )
        assert len(rows) == 1
        assert rows[0]["url"] == f"http://127.0.0.1:{port}/"

        explicit_scheme = run_cli(
            "-j",
            "-u",
            "http://127.0.0.1",
            "--no-fallback-scheme",
            "-p",
            f"HTTPS:{port}",
            "--match-code",
            "200",
        )
        assert len(explicit_scheme) == 1
        assert explicit_scheme[0]["url"] == f"http://127.0.0.1:{port}/"

        bad = run_cli_raw(
            "-j",
            "-u",
            "127.0.0.1",
            "--default-scheme",
            "http",
            "--no-fallback-scheme",
            "-p",
            "http:notaport",
        )
        assert bad.returncode == 2
        assert "invalid option value" in bad.stderr
        assert bad.stdout == ""

        bad_scheme = run_cli_raw(
            "-j",
            "-u",
            "127.0.0.1",
            "-p",
            "ftp:21",
        )
        assert bad_scheme.returncode == 2
        assert "invalid option value" in bad_scheme.stderr

        bad_empty_item = run_cli_raw(
            "-j",
            "-u",
            "127.0.0.1",
            "-p",
            "http:80,",
        )
        assert bad_empty_item.returncode == 2
        assert "invalid option value" in bad_empty_item.stderr
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_methods_are_validated():
    build_cli()
    bad_method = run_cli_raw(
        "-j",
        "-u",
        "http://127.0.0.1:1/",
        "-x",
        "GET,BA D",
        "--timeout",
        "1",
    )
    assert bad_method.returncode == 2
    assert "invalid option value" in bad_method.stderr
    assert bad_method.stdout == ""

    empty_method = run_cli_raw(
        "-j",
        "-u",
        "http://127.0.0.1:1/",
        "-x",
        "GET,",
        "--timeout",
        "1",
    )
    assert empty_method.returncode == 2
    assert "invalid option value" in empty_method.stderr
    assert empty_method.stdout == ""


def test_ci_httpx_integer_options_are_validated():
    build_cli()
    cases = [
        ("--timeout", "0"),
        ("--timeout", "abc"),
        ("--retries", "-1"),
        ("--max-redirects", "1x"),
        ("--body-preview-size", "-1"),
    ]

    for flag, value in cases:
        proc = run_cli_raw(
            "-j",
            "-u",
            "http://127.0.0.1:1/",
            flag,
            value,
        )
        assert proc.returncode == 2
        assert "invalid option value" in proc.stderr
        assert proc.stdout == ""


def test_ci_httpx_scheme_and_extract_preset_are_validated():
    build_cli()
    bad_scheme = run_cli_raw(
        "-j",
        "-u",
        "127.0.0.1",
        "--default-scheme",
        "ftp",
    )
    assert bad_scheme.returncode == 2
    assert "invalid option value" in bad_scheme.stderr
    assert bad_scheme.stdout == ""

    bad_preset = run_cli_raw(
        "-j",
        "-u",
        "http://127.0.0.1:1/",
        "--extract-preset",
        "phone",
        "--timeout",
        "1",
    )
    assert bad_preset.returncode == 2
    assert "invalid option value" in bad_preset.stderr
    assert bad_preset.stdout == ""


def test_ci_httpx_path_files_and_comma_lists_are_validated(tmp_path):
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    path_file = tmp_path / "paths.txt"
    path_file.write_text("\n# ignored\n/\n/final\n", encoding="utf-8")

    try:
        port = server.server_port
        rows = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}",
            "--path",
            str(path_file),
            "--match-code",
            "200",
        )
        assert [row["path"] for row in rows] == ["/", "/final"]

        long_path = "/" + ("a" * 9000)
        long_path_file = tmp_path / "long-path.txt"
        long_path_file.write_text(long_path + "\n", encoding="utf-8")
        long_rows = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}",
            "--path",
            str(long_path_file),
            "--match-code",
            "200",
        )
        assert len(long_rows) == 1
        assert long_rows[0]["path"] == long_path
        assert REQUESTS[-1]["path"] == long_path

        bad_path = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}",
            "--path",
            "/,",
        )
        assert bad_path.returncode == 2
        assert "invalid option value" in bad_path.stderr
        assert bad_path.stdout == ""

        bad_resolver = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}",
            "-r",
            "1.1.1.1,",
        )
        assert bad_resolver.returncode == 2
        assert "invalid option value" in bad_resolver.stderr
        assert bad_resolver.stdout == ""
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_matcher_and_filter_expressions_are_validated():
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        port = server.server_port
        bad_match = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-code",
            "200,bad",
        )
        assert bad_match.returncode == 2
        assert "invalid option value" in bad_match.stderr
        assert bad_match.stdout == ""

        bad_empty_match = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-code",
            "200,",
        )
        assert bad_empty_match.returncode == 2
        assert "invalid option value" in bad_empty_match.stderr
        assert bad_empty_match.stdout == ""

        bad_time = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-response-time",
            "soon",
        )
        assert bad_time.returncode == 2
        assert "invalid option value" in bad_time.stderr
        assert bad_time.stdout == ""

        bad_match_regex = run_cli_raw(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-regex",
            "admin,[",
        )
        assert bad_match_regex.returncode == 2
        assert "invalid option value" in bad_match_regex.stderr
        assert bad_match_regex.stdout == ""

        matched_hour = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "--match-response-time",
            "< 1h",
        )
        assert len(matched_hour) == 1

        filtered = run_cli(
            "-j",
            "-u",
            f"http://127.0.0.1:{port}/",
            "-frt",
            ">= 0us",
        )
        assert filtered == []
    finally:
        server.shutdown()
        server.server_close()


def test_ci_httpx_library_callback_can_write_httpx_json(tmp_path):
    build_cli()
    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    source = tmp_path / "callback_json.c"
    binary = tmp_path / "callback_json"
    output = tmp_path / "callback.jsonl"
    source.write_text(
        r'''
#include "ci_httpx.h"

#include <stdio.h>

static int on_result(const cihx_result *result, void *userdata)
{
  FILE *fp = (FILE *)userdata;
  if(!result->port || !result->headers || result->header_count == 0)
    return 9;
  return cihx_result_write_json(fp, result);
}

int main(int argc, char **argv)
{
  cihx_options *opts;
  FILE *fp;
  int rc;

  if(argc != 3)
    return 2;
  opts = cihx_options_new();
  if(!opts)
    return 3;
  fp = fopen(argv[2], "w");
  if(!fp) {
    cihx_options_free(opts);
    return 4;
  }
  rc = cihx_options_add_target(opts, argv[1]);
  if(!rc)
    rc = cihx_options_set_match_status_code(opts, "200");
  if(!rc)
    rc = cihx_options_add_match_cdn(opts, "cloudflare");
  if(!rc)
    rc = cihx_options_add_filter_cdn(opts, "akamai");
  cihx_options_set_probe_flags(opts, CIHX_PROBE_STATUS_CODE);
  cihx_options_set_include_response_header(opts, 1);
  if(!rc)
    rc = cihx_run(opts, on_result, fp);
  fclose(fp);
  cihx_options_free(opts);
  return rc ? 1 : 0;
}
''',
        encoding="utf-8",
    )

    try:
        port = server.server_port
        subprocess.run(
            [
                "cc",
                "-I",
                str(ROOT / "httpxlib"),
                str(source),
                str(ROOT / "httpxlib" / "libci_httpx.a"),
                "-lcurl",
                "-o",
                str(binary),
            ],
            cwd=ROOT,
            check=True,
        )
        subprocess.run(
            [
                str(binary),
                f"http://127.0.0.1:{port}/,http://127.0.0.1:{port}/final",
                str(output),
            ],
            cwd=ROOT,
            check=True,
        )
        rows = [
            json.loads(line)
            for line in output.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(rows) == 2
        assert rows[0]["url"] == f"http://127.0.0.1:{port}/"
        assert rows[0]["port"] == str(port)
        assert rows[0]["status_code"] == 200
        assert rows[0]["header"]["Server"] == "cloudflare-test"
        assert rows[1]["url"] == f"http://127.0.0.1:{port}/final"
        assert rows[1]["title"] == "Final Page"
    finally:
        server.shutdown()
        server.server_close()
