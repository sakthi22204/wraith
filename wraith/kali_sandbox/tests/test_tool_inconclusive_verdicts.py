"""A scan that never reached a verdict must not be reported as a clean target.

`run_sqlmap` decided its verdict with a single line:

    vulnerable = "is vulnerable" in res["stdout"] or "Payload:" in res["stdout"]

`run_tool` returns empty stdout for the two failures operators actually hit -- a
timeout against a slow target, and a binary missing from the image. Both
markers are then False, so the tool returned `vulnerable=False`. That is the
most dangerous possible way to be wrong: a hung scan, or a container without
sqlmap installed, was indistinguishable from a target that was scanned and
found clean. The one signal an operator needs most -- "this told me nothing" --
was exactly the one that got thrown away.

The same marker-check shape was in `run_module` (metasploit), where an empty
stdout turned a timeout into "the exploit did not land".

The verdict is now three-state. None means no conclusion was reached; only
sqlmap's own conclusion lines can produce True or False.
"""

import pytest

from mcp_servers.common.parsers import MetasploitResult, SQLMapResult
from mcp_servers.metasploit_server import MetasploitServer
from mcp_servers.sqlmap_server import SQLMAP_TIMEOUT_SECONDS, SQLMapServer


# Verbatim sqlmap lines. Both directions are load-bearing.
SQLMAP_FINDS_IT = """
[INFO] testing parameter 'id' on parameter clause 1
[INFO] the back-end DBMS is MySQL
Parameter: id
Payload: id=1 AND SLEEP(5)
---
id=1 AND SLEEP(5)
is vulnerable to SQL injection. Your payload is: id=1 AND SLEEP(5)
"""

SQLMAP_FINDS_NOTHING = """
[INFO] testing parameter 'id' on parameter clause 1
[WARNING] URI parameter '#1*' does not seem to be injectable
[CRITICAL] all tested parameters do not appear to be injectable
Injection is not possible. Status: Not Injectable
"""

# What a scan that was killed mid-run leaves behind: progress lines, no summary.
SQLMAP_TRUNCATED = """
[INFO] testing parameter 'id' on parameter clause 1
[INFO] testing 2nd possible injection techniques
"""

# run_tool's timeout/missing-binary path, per _result() defaults.
NO_OUTPUT = {"stdout": "", "stderr": "", "exit_code": -1, "success": False,
             "error": "Tool timed out after 1800s"}


def _sqlmap_server(monkeypatch):
    """A server whose subprocess layer returns a canned run_tool result."""
    srv = SQLMapServer()
    monkeypatch.setattr(srv, "verify_caller", lambda *a, **k: None)
    monkeypatch.setattr(srv, "validate_target", lambda *a, **k: None)
    return srv


def _msf_server(monkeypatch):
    srv = MetasploitServer()
    monkeypatch.setattr(srv, "verify_caller", lambda *a, **k: None)
    monkeypatch.setattr(srv, "validate_target", lambda *a, **k: None)
    return srv


def _stub_run_tool(srv, monkeypatch, result):
    async def _run_tool(cmd, timeout=None):
        return result
    monkeypatch.setattr(srv, "run_tool", _run_tool)


def _tool(srv, name):
    """The coroutine behind an `@self.mcp.tool()` registration.

    Those are closures captured in the server's ToolManager, not attributes on
    the instance, so the call sites have to be reached through it.
    """
    return srv.mcp._tool_manager.get_tool(name).fn


# --- the regression --------------------------------------------------------


@pytest.mark.asyncio
async def test_a_timeout_is_not_reported_as_a_clean_target(monkeypatch):
    """The bug: empty stdout used to come back as vulnerable=False."""
    srv = _sqlmap_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, dict(NO_OUTPUT))

    res = await _tool(srv, "run_sqlmap")(url="https://toom.de/s/x")

    assert res.vulnerable is None, (
        "a timed-out scan was reported as a verdict; it reached no conclusion"
    )
    assert res.inconclusive is True
    assert "timed out" in res.raw_output, (
        "the operator loses the reason the scan failed entirely"
    )


@pytest.mark.asyncio
async def test_a_missing_binary_is_not_reported_as_a_clean_target(monkeypatch):
    srv = _sqlmap_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": "", "stderr": "", "exit_code": -1, "success": False,
        "error": "definitely_not_installed_tool",
    })

    res = await _tool(srv, "run_sqlmap")(url="https://toom.de/s/x")

    assert res.vulnerable is None
    assert res.inconclusive is True
    assert "definitely_not_installed_tool" in res.raw_output


@pytest.mark.asyncio
async def test_truncated_output_is_not_reported_as_a_clean_target(monkeypatch):
    """Progress lines but no summary: still no verdict, so still not False."""
    srv = _sqlmap_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": SQLMAP_TRUNCATED, "stderr": "", "exit_code": -9, "success": False,
    })

    res = await _tool(srv, "run_sqlmap")(url="https://toom.de/s/x")

    assert res.vulnerable is None, "an unfinished scan was reported as a verdict"
    assert res.inconclusive is True


# --- the verdicts still work ----------------------------------------------


@pytest.mark.asyncio
async def test_a_real_negative_verdict_is_false(monkeypatch):
    srv = _sqlmap_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": SQLMAP_FINDS_NOTHING, "stderr": "", "exit_code": 0, "success": True,
    })

    res = await _tool(srv, "run_sqlmap")(url="https://api.toom.de/public/api/markets/3248")

    assert res.vulnerable is False, "a completed negative scan lost its verdict"
    assert res.inconclusive is False


@pytest.mark.asyncio
async def test_a_real_positive_verdict_is_true(monkeypatch):
    srv = _sqlmap_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": SQLMAP_FINDS_IT, "stderr": "", "exit_code": 0, "success": True,
    })

    res = await _tool(srv, "run_sqlmap")(url="https://api.toom.de/public/api/markets/3248")

    assert res.vulnerable is True
    assert res.inconclusive is False


@pytest.mark.asyncio
async def test_a_negative_verdict_survives_a_non_zero_exit(monkeypatch):
    """sqlmap reports 'not injectable' with a non-zero exit status.

    test_run_tool_result_shape.py pins that: the tool servers must not treat
    exit status as the verdict. Gating the inconclusive branch on
    res["success"] would have broken this case, so it is guarded explicitly.
    """
    srv = _sqlmap_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": SQLMAP_FINDS_NOTHING, "stderr": "some noise", "exit_code": 1,
        "success": False,
    })

    res = await _tool(srv, "run_sqlmap")(url="https://api.toom.de/public/api/markets/3248")

    assert res.vulnerable is False
    assert res.inconclusive is False


@pytest.mark.asyncio
async def test_negative_verdict_output_is_preserved_for_the_operator(monkeypatch):
    """The raw evidence must survive even on a non-zero exit."""
    srv = _sqlmap_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": SQLMAP_FINDS_NOTHING, "stderr": "", "exit_code": 1, "success": False,
    })

    res = await _tool(srv, "run_sqlmap")(url="https://toom.de/s/x")

    assert "do not appear to be injectable" in res.raw_output


# --- metasploit, same shape -----------------------------------------------


@pytest.mark.asyncio
async def test_an_msf_timeout_is_not_reported_as_a_failed_exploit(monkeypatch):
    srv = _msf_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, dict(NO_OUTPUT))

    res = await _tool(srv, "run_module")(
        module="auxiliary/scanner/smb/smb_enum", target="https://toom.de",
        options={},
    )

    assert res.success is False
    assert res.inconclusive is True, (
        "a hung msfconsole was reported as 'the exploit did not land'"
    )
    assert res.raw_output


@pytest.mark.asyncio
async def test_an_msf_run_that_opened_a_session_is_a_success(monkeypatch):
    srv = _msf_server(monkeypatch)
    _stub_run_tool(srv, monkeypatch, {
        "stdout": "[*] Session 1 opened\n[+] Exploit completed\n",
        "stderr": "", "exit_code": 0, "success": True,
    })

    res = await _tool(srv, "run_module")(
        module="auxiliary/scanner/smb/smb_enum", target="https://toom.de",
        options={},
    )

    assert res.success is True
    assert res.inconclusive is False
    assert res.session_info["session_id"] == "1"


# --- the timeout ceiling ---------------------------------------------------


def test_the_timeout_can_outlast_a_risk2_level3_scan():
    """--risk=2 --level=3 does not finish in 600s against a real target.

    Both gated runs on toom.de/api.toom.de expired at the old ceiling and
    returned vulnerable=False, which is what the tests above exist to prevent.
    """
    assert SQLMAP_TIMEOUT_SECONDS >= 900, (
        f"{SQLMAP_TIMEOUT_SECONDS}s is too short for --risk=2 --level=3; the scan "
        "will time out and now correctly report inconclusive, i.e. no result at all"
    )


# --- the model itself carries the distinction ------------------------------


def test_the_result_model_can_represent_unknown():
    """None and False must stay distinguishable in the schema itself.

    If vulnerable were bool again, a caller serialising the result would turn
    "we don't know" back into "it is fine".
    """
    assert SQLMapResult(target="x").vulnerable is None
    assert SQLMapResult(target="x", vulnerable=False).vulnerable is False
    assert SQLMapResult(target="x", vulnerable=None).inconclusive is False
    assert MetasploitResult(module="m", success=False, inconclusive=True).inconclusive