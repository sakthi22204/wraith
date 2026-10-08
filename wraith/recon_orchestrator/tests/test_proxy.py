"""Interception gating. When RECON_PROXY_URL is empty every helper must be inert.

An enabled-by-default proxy would change egress for every target, so the disabled
path is the one that has to be boring: empty dicts, empty string, no extra_hosts.
The enabled path has to carry three things together -- the proxy URL, the CA
bundle the tool trusts, and the read-only mount that delivers the CA -- because
a tool that trusts the CA without the mount, or has the mount without
REQUESTS_CA_BUNDLE, fails TLS against an intercepted host.
"""
import pytest

from app.tools import proxy as proxy_mod


@pytest.fixture
def off(monkeypatch):
    monkeypatch.setattr(proxy_mod.settings, "RECON_PROXY_URL", "")
    return proxy_mod


@pytest.fixture
def on(monkeypatch):
    monkeypatch.setattr(proxy_mod.settings, "RECON_PROXY_URL", "http://mitmproxy_sidecar:8080")
    return proxy_mod


def test_disabled_by_default_is_inert(off):
    assert off.proxy_enabled() is False
    assert off.proxy_http_url() == ""
    assert off.proxy_env() == {}
    assert off.proxy_volumes() == {}
    assert off.proxy_extra_hosts() == {}
    assert off.add_proxy_flags(["-u", "x"], "-http-proxy") == ["-u", "x"]


def test_enabled_proxy_url_is_passed_through(on):
    assert on.proxy_enabled() is True
    assert on.proxy_http_url() == "http://mitmproxy_sidecar:8080"
    assert on.proxy_host() == "mitmproxy_sidecar"


def test_scheme_is_added_when_missing(monkeypatch):
    monkeypatch.setattr(proxy_mod.settings, "RECON_PROXY_URL", "mitmproxy_sidecar:8080")
    assert proxy_mod.proxy_http_url() == "http://mitmproxy_sidecar:8080"


def test_ca_is_mounted_read_only_from_a_named_volume(on):
    """A named volume, not a host bind: the broker only allows named volumes."""
    volumes = on.proxy_volumes()

    assert list(volumes) == ["mitmproxy_ca"]
    assert volumes["mitmproxy_ca"]["bind"] == "/etc/mitmproxy-ca"
    assert volumes["mitmproxy_ca"]["mode"] == "ro"


def test_ca_bundle_env_points_at_the_mounted_path(on):
    env = on.proxy_env()

    for key in ("REQUESTS_CA_BUNDLE", "SSL_CERT_FILE", "CURL_CA_BUNDLE"):
        assert env[key] == "/etc/mitmproxy-ca/mitmproxy-ca-cert.pem"
    assert env["HTTPS_PROXY"] == "http://mitmproxy_sidecar:8080"
    assert env["HTTP_PROXY"] == "http://mitmproxy_sidecar:8080"


def test_local_hosts_are_never_proxied(on):
    """juice_shop and the docker network must stay direct.

    Proxying them would break the local test target and make every in-network
    hop a TLS interception it does not need.
    """
    env = on.proxy_env()

    for entry in ("localhost", "127.0.0.1", "juice_shop", "mitmproxy"):
        assert entry in env["NO_PROXY"]
        assert entry in env["no_proxy"]


def test_tool_flags_gain_the_proxy(on):
    assert on.add_proxy_flags(["-u", "docs.arc.io"], "-http-proxy") == [
        "-u", "docs.arc.io", "-http-proxy", "http://mitmproxy_sidecar:8080",
    ]
    # katana spells the same idea differently; the helper must not hardcode one.
    assert on.add_proxy_flags(["-u", "docs.arc.io"], "-proxy", "socks5://x:1")[-1] == "socks5://x:1"


def test_extra_hosts_unresolvable_is_empty_not_an_error(on, monkeypatch):
    """A DNS miss must degrade to no extra_hosts, not raise into the tool run."""
    import socket

    def fail(host):
        raise OSError("no address")
    # proxy.py imports socket inside the function, so patch the module itself.
    monkeypatch.setattr(socket, "gethostbyname", fail)

    assert on.proxy_extra_hosts() == {}
