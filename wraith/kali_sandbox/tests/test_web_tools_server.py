"""The Phase 1.9 web scanners must hand back an honest tri-state verdict.

The scanners are automation run against a caller-supplied URL, and the two
failure modes an operator actually hits -- a timeout, a missing binary, a tool
absent from the image -- all produce empty stdout. Deciding "clean" from that
would report an infrastructure failure as a cleared target, which is the same
most-dangerous-possible-way-to-be-wrong the sqlmap/metasploit verdicts were
fixed for. Every scanner returns `inconclusive=True` for no output, and a
tool's own conclusion lines alone decide the positive direction.

The parsers are module-level so each scanner's signal extraction is tested
without spawning anything. The `_scan` path is tested through the tool closures
with a stubbed subprocess layer, mirroring test_tool_inconclusive_verdicts.py.
"""

import pytest

from mcp_servers.common.base_server import BaseSecurityServer
from mcp_servers.web_tools_server import (
    WebToolsServer,
    parse_arjun,
    parse_commix,
    parse_corsy,
    parse_dalfox,
    parse_ghauri,
    parse_jwt_tool,
    parse_nikto,
    parse_xsstrike,
)

NO_OUTPUT = {"stdout": "", "stderr": "", "exit_code": -1, "success": False,
             "error": "Tool timed out after 300s"}


def _server(monkeypatch):
    srv = WebToolsServer()
    monkeypatch.setattr(srv, "verify_caller", lambda *a, **k: None)
    monkeypatch.setattr(srv, "validate_url", lambda *a, **k: None)
    return srv


def _stub_run_tool(srv, monkeypatch, result):
    async def _run_tool(cmd, timeout=None):
        return result
    monkeypatch.setattr(srv, "run_tool", _run_tool)


def _tool(srv, name):
    return srv.mcp._tool_manager.get_tool(name).fn


# --- validate_url: the URL-safe validator admits queries, rejects shell casing


class TestValidateUrl:
    def _server(self):
        return BaseSecurityServer("test")

    def test_query_strings_and_fragments_are_valid(self):
        srv = self._server()
        for url in (
            "http://host:8080/?id=1&x=2&y=a+b",
            "https://host/path;jsessionid=ABC?q=%2Fetc",
            "http://[::1]:8080/",
            "http://juice-shop/search?q=canary",
        ):
            assert srv.validate_url(url) == url

    def test_scheme_must_be_http_or_https(self):
        with pytest.raises(ValueError):
            self._server().validate_url("ftp://host/")
        with pytest.raises(ValueError):
            self._server().validate_url("file:///etc/passwd")

    def test_no_host_is_refused(self):
        for url in ("http://", "https://?id=1", ""):
            with pytest.raises(ValueError):
                self._server().validate_url(url)

    def test_shell_casing_is_refused(self):
        srv = self._server()
        for url in (
            "http://host/ ; ls -la",
            "http://host/\nsystem('id')",
            "http://host/`cat /etc/passwd`",
            "http://host/$(id)",
            "http://host/{evil}",
            "http://host/|id",
            "http://host/\"id\"",
            "http://host/'id'",
            "http://host\\id",
        ):
            with pytest.raises(ValueError):
                srv.validate_url(url)


# --- the parsers extract the scanners' own signals -------------------------


class TestParsers:
    def test_arjun_reports_found_parameters(self):
        out = parse_arjun("[+] Finished\n[+] Found parameters: uid, pass, q\n")
        assert out == ["parameters: uid, pass, q"]

    def test_arjun_reports_its_current_word_order_and_source(self):
        out = parse_arjun(
            "[!] Processing chunks: 1/1\n"
            "\x1b[1;92m[\u2713]\x1b[0m parameter detected: q, based on: "
            "http headers | \x1b[1;32m[+]\x1b[0m Parameters found: q\n"
        )
        assert out == ["parameter detected: q (based on: http headers)"]

    def test_arjun_current_summary_word_order_is_read_too(self):
        out = parse_arjun("[+] Parameters found: uid, pass\n")
        assert out == ["parameters: uid, pass"]

    def test_dalfox_reports_poc_lines(self):
        out = parse_dalfox(
            "[I] loading\n[P] [POC][GET][https://h/][reflected]\n[P] [POC] url\ndone\n"
        )
        assert len(out) == 2
        assert "POC" in out[0] and "POC" in out[1]

    def test_dalfox_clean_run_has_no_findings(self):
        assert parse_dalfox("[I] no vulnerabilities\n") == []

    def test_corsy_surfaces_acao_headers(self):
        out = parse_corsy(
            "Request Header Origin: http://evil\n"
            "Response Header Access-Control-Allow-Origin: *\n"
            "Response Header Access-Control-Allow-Credentials: true\n"
        )
        assert len(out) == 2
        assert "Access-Control-Allow-Origin" in out[0]

    def test_corsy_surfaces_its_own_acao_report_format(self):
        out = parse_corsy(
            " - Class: wildcard value\n"
            " - Severity: low\n"
            " - ACAO Header: *\n"
            " - ACAC Header: None\n"
        )
        assert len(out) == 2
        assert "ACAO Header: *" in out[0]
        assert "ACAC Header: None" in out[1]

    def test_commix_conclusion_lines(self):
        assert parse_commix("[-] (not vulnerable)\n") == []
        assert parse_commix("[+] (vulnerable)\n") != []

    def test_commix_4x_conclusion_lines(self):
        # current commix drops the parenthesised verdict and phrases the
        # conclusion as a sentence instead.
        assert parse_commix(
            "[warning] GET parameter 'q' does not seem to be injectable.\n"
            "[critical] All tested parameters do not appear to be injectable.\n"
        ) == []
        assert parse_commix("The parameter 'q' seems to be injectable.\n") != []

    def test_ghauri_not_vulnerable_never_reads_as_positive(self):
        assert parse_ghauri("[INFO] parameter 'id' is not vulnerable\n") == []
        assert parse_ghauri("[INFO] URI parameter 'id' appears to be injectable\n") != []

    def test_jwt_tool_returns_decoded_blocks_and_alerts(self):
        out = parse_jwt_tool(
            "===============JWT DECODING===============\n"
            "*** Decoded Header ***\n{\"alg\":\"HS256\",\"typ\":\"JWT\"}\n\n"
            "*** Decoded Payload ***\n{\"sub\":\"1\",\"exp\":0}\n\n"
            "[!] SECURITY ISSUE: alg=none accepted\n"
        )
        assert any('"alg"' in line for line in out)
        assert any("SECURITY ISSUE" in line for line in out)

    def test_jwt_tool_surfaces_exploit_result_lines(self):
        out = parse_jwt_tool(
            "Decoded Token Values:\n"
            "[+] alg = \"RS256\"\n"
            "[+] typ = \"JWT\"\n\n"
            "jwttool_abc123 Exploit: \"alg\":\"none\" Response Code: 200, 8510 bytes\n"
        )
        assert any(line.startswith("jwttool_abc123") for line in out)
        assert any("alg" in line and "RS256" in line for line in out)

    def test_nikto_plus_lines_are_findings(self):
        out = parse_nikto(
            "- Nikto v2.5.0\n+ Server: nginx/1.18\n+ OSVDB-3092: /config.json\n"
        )
        assert out == ["Server: nginx/1.18", "OSVDB-3092: /config.json"]

    def test_xsstrike_finding_lines(self):
        out = parse_xsstrike(
            "[i] scanning\n[+] Reflected Content: <canary>\n[!] Better luck next time\n"
        )
        assert out == ["Reflected Content: <canary>"]


# --- the _scan path is tri-state -------------------------------------------


@pytest.mark.asyncio
async def test_a_timeout_is_inconclusive_for_every_scanner(monkeypatch):
    srv = _server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, dict(NO_OUTPUT))
    for name, body in (
        ("run_arjun", {"url": "https://h/"}),
        ("run_dalfox", {"url": "https://h/"}),
        ("run_corsy", {"url": "https://h/"}),
        ("run_commix", {"url": "https://h/"}),
        ("run_ghauri", {"url": "https://h/"}),
        ("run_jwt_tool", {"token": "e.e.e", "target": "https://h/"}),
        ("run_nikto", {"url": "https://h/"}),
        ("run_xsstrike", {"url": "https://h/"}),
    ):
        res = await _tool(srv, name)(**body)
        assert res.inconclusive is True, name
        assert res.findings == [], name
        assert "timed out" in res.raw_output, name


@pytest.mark.asyncio
async def test_a_missing_binary_is_inconclusive_not_clean(monkeypatch):
    srv = _server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": "", "stderr": "", "exit_code": -1, "success": False,
        "error": "no such file or directory: arjun",
    })
    res = await _tool(srv, "run_arjun")(url="https://h/")
    assert res.inconclusive is True
    assert "arjun" in res.raw_output


@pytest.mark.asyncio
async def test_a_positive_verdict_survives_a_non_zero_exit(monkeypatch):
    """Scanners report findings with a non-zero exit; exit status is not the
    verdict, exactly as with sqlmap."""
    srv = _server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": "[+] Found parameters: pin, otp\n", "stderr": "", "exit_code": 1,
        "success": False,
    })
    res = await _tool(srv, "run_arjun")(url="https://h/")
    assert res.inconclusive is False
    assert res.findings == ["parameters: pin, otp"]


@pytest.mark.asyncio
async def test_a_clean_run_is_clean_not_inconclusive(monkeypatch):
    srv = _server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": "[i] scan complete, nothing found\n", "stderr": "", "exit_code": 0,
        "success": True,
    })
    res = await _tool(srv, "run_xsstrike")(url="https://h/")
    assert res.inconclusive is False
    assert res.findings == []


@pytest.mark.asyncio
async def test_arjun_bailing_before_its_conclusion_is_inconclusive(monkeypatch):
    srv = _server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": "[!] Processing chunks: 1/1\n", "stderr": "", "exit_code": 0,
        "success": True,
    })
    res = await _tool(srv, "run_arjun")(url="https://h/?q=1")
    assert res.inconclusive is True

    _stub_run_tool(srv, monkeypatch, {
        "stdout": "[+] Parameters found: q\n", "stderr": "", "exit_code": 0,
        "success": True,
    })
    res = await _tool(srv, "run_arjun")(url="https://h/?q=1")
    assert res.inconclusive is False


@pytest.mark.asyncio
async def test_commix_is_forced_out_of_stdin_target_mode(monkeypatch):
    """A piped stdin makes commix ignore -u and exit after its banner. That
    reads as a clean verdict, so the invocation must name URL mode and answer
    the 500-skip prompt instead of letting the batch default bail out."""
    srv = _server(monkeypatch)
    seen = {}

    async def _run_tool(cmd, timeout=None):
        seen["cmd"] = cmd
        return {"stdout": "[-] (not vulnerable)\n", "stderr": "", "exit_code": 0,
                "success": True}

    monkeypatch.setattr(srv, "run_tool", _run_tool)
    res = await _tool(srv, "run_commix")(url="https://h/?q=1", param="q")

    assert "--ignore-stdin" in seen["cmd"]
    assert any(arg.startswith("--answers=") for arg in seen["cmd"])
    assert res.inconclusive is False


@pytest.mark.asyncio
async def test_commix_bailing_before_testing_is_inconclusive(monkeypatch):
    """The banner plus a skipped scan is not a "not vulnerable" conclusion."""
    srv = _server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": ("banner\n[info] Skipping further testing on the target "
                   "URL.\n"),
        "stderr": "", "exit_code": 0, "success": True,
    })
    res = await _tool(srv, "run_commix")(url="https://h/?q=1")
    assert res.inconclusive is True
    assert res.findings == []


@pytest.mark.asyncio
async def test_ghauri_bailing_before_testing_is_inconclusive(monkeypatch):
    srv = _server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": "[INFO] testing connection to the target URL\n",
        "stderr": "", "exit_code": 0, "success": True,
    })
    res = await _tool(srv, "run_ghauri")(url="https://h/?q=1")
    assert res.inconclusive is True

    _stub_run_tool(srv, monkeypatch, {
        "stdout": "[INFO] parameter 'q' is not vulnerable\n",
        "stderr": "", "exit_code": 0, "success": True,
    })
    res = await _tool(srv, "run_ghauri")(url="https://h/?q=1")
    assert res.inconclusive is False