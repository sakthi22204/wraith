"""FULL_TOOL_ACCESS bypasses the caller floor and the grant/scope gate."""

from types import SimpleNamespace

import mcp_servers.main as main_mod


def test_verify_caller_is_a_noop_when_full_tool_access(monkeypatch):
    monkeypatch.setattr(
        main_mod, "sandbox_settings", SimpleNamespace(FULL_TOOL_ACCESS=True)
    )
    # Would raise otherwise: run_hydra with an unauthorized caller, and a
    # non-dangerous tool with no caller identity at all.
    main_mod.verify_caller("run_hydra", None)
    main_mod.verify_caller("run_nmap_scan", None)


def test_gate_request_is_a_noop_when_full_tool_access(monkeypatch):
    monkeypatch.setattr(
        main_mod, "sandbox_settings", SimpleNamespace(FULL_TOOL_ACCESS=True)
    )
    # No destination and no grant: gated, this would raise before dispatch.
    main_mod.gate_request("run_sqlmap", {})
    main_mod.gate_request("http_probe", {})
