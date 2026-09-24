"""Optional egress interception for recon tools via an intercepting proxy.

When RECON_PROXY_URL is configured (e.g. "http://mitmproxy:8080"), supported
HTTP(S) tools (httpx, katana) route their traffic through that proxy and trust
its CA, so the orchestrator can persist decrypted request/response evidence.

When RECON_PROXY_URL is empty (the default) every helper returns empty
dicts / "". Tool behaviour is byte-identical to running without a proxy — this
module is the single gating authority.

The broker already forwards environment / volumes / extra_hosts verbatim
(containers.run(image, command, **spec)); it only rejects privileged,
host-network/pid/ipc, and bind-mount host paths. Named volumes and
env/extra_hosts pass through unchanged -> NO broker code changes required.
"""
import logging
import re
from typing import Dict, List, Optional

from ..config import settings

logger = logging.getLogger(__name__)

# Named volume that carries the proxy's CA (mountable read-only into tool
# containers). Broker allows named volumes; it only blocks host-path bind mounts.
CA_VOLUME = "mitmproxy_ca"
# Where tool containers will find the CA so they trust the intercepted TLS.
CA_BUNDLE_DIR = "/etc/mitmproxy-ca"
CA_BUNDLE = f"{CA_BUNDLE_DIR}/mitmproxy-ca-cert.pem"


def proxy_http_url() -> str:
    """http://HOST:PORT the tools use as their HTTP(S) proxy, or '' when off."""
    raw = (settings.RECON_PROXY_URL or "").strip()
    if not raw:
        return ""
    return raw if "://" in raw else f"http://{raw}"


def proxy_enabled() -> bool:
    return bool(proxy_http_url())


def proxy_host() -> str:
    m = re.match(r"https?://([^:/]+)", proxy_http_url())
    return m.group(1) if m else ""


def proxy_env() -> Dict[str, str]:
    """Env injected into tool containers so their HTTP(S) egress goes through
    the proxy AND trusts its CA. Empty when disabled -> no behaviour change."""
    if not proxy_enabled():
        return {}
    return {
        "HTTP_PROXY": proxy_http_url(),
        "HTTPS_PROXY": proxy_http_url(),
        "http_proxy": proxy_http_url(),
        "https_proxy": proxy_http_url(),
        "ALL_PROXY": proxy_http_url(),
        "all_proxy": proxy_http_url(),
        "NO_PROXY": "localhost,127.0.0.1,0.0.0.0,docker_broker,recon_orchestrator,neo4j,juice_shop,login,mitmproxy",
        "no_proxy": "localhost,127.0.0.1,0.0.0.0,docker_broker,recon_orchestrator,neo4j,juice_shop,login,mitmproxy",
        # Trust the proxy CA for common runtimes:
        "REQUESTS_CA_BUNDLE": CA_BUNDLE,
        "SSL_CERT_FILE": CA_BUNDLE,
        "CURL_CA_BUNDLE": CA_BUNDLE,
        "REQUESTS_CA_BUNDLE_FALLBACK": CA_BUNDLE,
    }


def proxy_volumes() -> Dict[str, dict]:
    """Read-only mount of the named CA volume into tool containers.
    Empty when disabled. Uses a NAMED volume (not a host bind) -> broker-safe."""
    if not proxy_enabled():
        return {}
    return {CA_VOLUME: {"bind": CA_BUNDLE_DIR, "mode": "ro"}}


def proxy_extra_hosts() -> Dict[str, str]:
    """Map the proxy hostname to its container IP via extra_hosts so Go-based
    tools (which resolve single-label names through /etc/hosts, not Docker DNS)
    can reach the proxy even when they skip NO_PROXY. Empty when disabled."""
    if not proxy_enabled():
        return {}
    host = proxy_host()
    if not host:
        return {}
    import socket
    try:
        return {host: socket.gethostbyname(host)}
    except OSError:
        logger.warning(f"proxy_extra_hosts: could not resolve proxy host '{host}'")
        return {}


def add_proxy_flags(flags: List[str], proxy_flag: str, proxy_arg: Optional[str] = None) -> List[str]:
    """Append the tool's proxy CLI flag(s) when interception is enabled.
    Returns the input list untouched when disabled -> byte-identical default."""
    if not proxy_enabled():
        return flags
    target = proxy_arg if proxy_arg is not None else proxy_http_url()
    return list(flags) + [proxy_flag, target]
