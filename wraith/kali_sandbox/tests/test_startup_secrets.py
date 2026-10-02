"""The sandbox must refuse to start without a usable gate secret.

GATE_SECRET is shared with active_exploit_runner and is what the sandbox uses to
verify a grant. With it unset the sandbox refuses every request, which is safe
but indistinguishable at a glance from a target that is refusing connections.
Refusing to start makes the cause explicit.

These are unit tests over the validator itself; they import no MCP SDK, but the
directory is still skipped on a host without it (see conftest.py), so this suite
runs with ``scripts/run_tests.sh sandbox``.
"""
import pytest

from mcp_servers.config import (
    KNOWN_INSECURE_SECRETS,
    Settings,
    validate_startup_secrets,
)


def test_a_real_secret_is_accepted():
    validate_startup_secrets(Settings(GATE_SECRET="a-generated-32-byte-secret"))


def test_an_empty_secret_is_refused():
    with pytest.raises(RuntimeError, match="GATE_SECRET is empty"):
        validate_startup_secrets(Settings(GATE_SECRET=""))


def test_a_whitespace_secret_is_refused():
    """Whitespace would make the HMAC key trivially guessable while looking
    configured, so it is treated as unset."""
    with pytest.raises(RuntimeError, match="GATE_SECRET is empty"):
        validate_startup_secrets(Settings(GATE_SECRET="   "))


@pytest.mark.parametrize("value", sorted(KNOWN_INSECURE_SECRETS - {""}))
def test_no_published_default_is_accepted(value):
    with pytest.raises(RuntimeError, match="published in this repository"):
        validate_startup_secrets(Settings(GATE_SECRET=value))


def test_the_validator_reads_the_module_settings_by_default(monkeypatch):
    """The startup call site passes no argument, so the default must be the
    module-level settings object that the environment populated."""
    monkeypatch.setattr(
        "mcp_servers.config.settings", Settings(GATE_SECRET="")
    )
    with pytest.raises(RuntimeError):
        validate_startup_secrets()


def test_a_blank_setting_object_is_refused():
    """A settings object with the field missing entirely must not be read as a
    pass, since getattr-style access is how this gets called elsewhere."""
    class Bare:
        pass

    with pytest.raises(RuntimeError):
        validate_startup_secrets(Bare())