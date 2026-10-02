"""Every `run_tool` exit path must return the same keys.

`run_tool` had three returns: a success path with stdout/stderr, and two failure
paths without them. The tool servers index `res["stdout"]` unconditionally --
nmap hands it straight to the XML parser, sqlmap does `"is vulnerable" in
res["stdout"]`, hydra and metasploit split it into lines -- so any failure
raised KeyError inside the parser instead of reaching the error branch.

The two failure paths are exactly the two an operator hits in practice:

  * a timeout, when a scan hangs against a filtered port
  * a missing binary, when a tool is not installed on the image

Both reported as "KeyError: 'stdout'". The reason the scan failed was in the
return value the whole time; the shape just discarded it before anyone could
read it.
"""

import asyncio

import pytest

from mcp_servers.common.base_server import BaseSecurityServer


REQUIRED_KEYS = {"stdout", "stderr", "exit_code", "success"}


class _FakeProcess:
    """Stands in for an asyncio subprocess."""

    def __init__(self, stdout=b"", stderr=b"", returncode=0, hang=False):
        self._stdout = stdout
        self._stderr = stderr
        self.returncode = returncode
        self._hang = hang
        self.killed = False
        self.waited = False

    async def communicate(self):
        if self._hang:
            await asyncio.sleep(3600)
        return self._stdout, self._stderr

    def kill(self):
        self.killed = True

    async def wait(self):
        self.waited = True
        return -9


@pytest.fixture
def server():
    return BaseSecurityServer("test")


def _patch_exec(monkeypatch, process):
    async def _fake_exec(*cmd, **kwargs):
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _fake_exec)


# --- the invariant ---------------------------------------------------------


@pytest.mark.asyncio
async def test_success_path_has_the_full_shape(server, monkeypatch):
    _patch_exec(monkeypatch, _FakeProcess(stdout=b"ok\n", stderr=b"", returncode=0))

    res = await server.run_tool(["echo", "ok"])

    assert REQUIRED_KEYS <= set(res), f"missing {REQUIRED_KEYS - set(res)}"
    assert res["stdout"] == "ok\n"
    assert res["success"] is True
    assert "error" not in res


@pytest.mark.asyncio
async def test_nonzero_exit_still_has_the_full_shape(server, monkeypatch):
    """A tool that ran and failed is not a shape error.

    `success` is False here but the command really did produce output, and
    parsers need it: nmap returns non-zero on some scans and sqlmap reports
    "not vulnerable" that way.
    """
    _patch_exec(monkeypatch, _FakeProcess(stdout=b"partial", stderr=b"warn", returncode=1))

    res = await server.run_tool(["false"])

    assert REQUIRED_KEYS <= set(res), f"missing {REQUIRED_KEYS - set(res)}"
    assert res["stdout"] == "partial"
    assert res["stderr"] == "warn"
    assert res["exit_code"] == 1
    assert res["success"] is False


@pytest.mark.asyncio
async def test_timeout_path_has_the_full_shape(server, monkeypatch):
    """The KeyError case: a hung scan must still yield a parsable dict."""
    process = _FakeProcess(hang=True)
    _patch_exec(monkeypatch, process)

    res = await server.run_tool(["nmap", "-sS", "10.255.255.1"], timeout=1)

    assert REQUIRED_KEYS <= set(res), f"missing {REQUIRED_KEYS - set(res)}"
    assert res["stdout"] == ""
    assert res["stderr"] == ""
    assert res["exit_code"] == -1
    assert res["success"] is False
    assert "timed out" in res["error"]
    assert process.killed, "the child was left running after a timeout"


@pytest.mark.asyncio
async def test_timeout_reaps_the_child(server, monkeypatch):
    """Killing without waiting leaves a zombie until the loop's own cleanup.

    Repeated timeouts then accumulate killed-but-unreaped processes, which is
    the situation where a server is already in trouble.
    """
    process = _FakeProcess(hang=True)
    _patch_exec(monkeypatch, process)

    await server.run_tool(["sleep", "infinity"], timeout=1)

    assert process.waited, "killed without being reaped"


@pytest.mark.asyncio
async def test_missing_binary_path_has_the_full_shape(server, monkeypatch):
    """The other KeyError case: a tool absent from the image.

    The OSError message names the missing executable and is the only clue
    available, so it has to survive into the return value.
    """
    async def _boom(*cmd, **kwargs):
        raise FileNotFoundError(2, "No such file or directory", cmd[0])

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _boom)

    res = await server.run_tool(["definitely_not_installed_tool"])

    assert REQUIRED_KEYS <= set(res), f"missing {REQUIRED_KEYS - set(res)}"
    assert res["stdout"] == ""
    assert res["stderr"] == ""
    assert res["exit_code"] == -1
    assert res["success"] is False
    assert "definitely_not_installed_tool" in res["error"], (
        "the missing executable name was dropped; the operator is left with a "
        "generic error and no way to tell which tool is absent"
    )


# --- what the fix is actually for ------------------------------------------


@pytest.mark.parametrize("server_file", [
    "mcp_servers/nmap_server.py",
    "mcp_servers/sqlmap_server.py",
    "mcp_servers/hydra_server.py",
    "mcp_servers/metasploit_server.py",
])
def test_every_server_indexes_stdout_directly(server_file):
    """Pins the coupling that made the shape matter.

    These are the call sites that raised the KeyError. They index rather than
    .get() on purpose -- a tool that produced no stdout is a real failure worth
    surfacing loudly, not something to paper over with a default. The fix is that
    the key is now always present, not that the parsers were made lenient.
    """
    import os
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(root, server_file)) as fh:
        source = fh.read()

    assert 'res["stdout"]' in source, f"{server_file} no longer reads stdout"


@pytest.mark.asyncio
async def test_a_parser_can_consume_a_failed_run(server, monkeypatch):
    """End to end: the failure dict survives being handed to a real parser.

    This is the shape the bug actually took in production -- run_tool returned a
    dict, and the caller blew up reading it.
    """
    _patch_exec(monkeypatch, _FakeProcess(hang=True))

    res = await server.run_tool(["nmap", "10.255.255.1"], timeout=1)

    # What the tool servers do on this path: index stdout, split it into lines,
    # and run marker checks over it. Before the fix the first line raised
    # KeyError; now the checks simply come back false, which is the truth --
    # a run that timed out found nothing.
    assert res["stdout"].split("\n") == [""]
    assert ("is vulnerable" in res["stdout"]) is False
    assert ("Payload:" in res["stdout"]) is False
    assert res.get("error") or res.get("stderr")
