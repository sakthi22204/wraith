"""``host:port`` for a destination, in one place.

Grants bind an authority rather than a bare hostname, and the sandbox recomputes
it independently and compares. That matters once a tool can choose the port it
dials: a grant naming only ``example.com`` would authorise every port on that
host, which is a far larger grant than the one the gates approved.

This lived in ``validation.py`` and was reached for by the action executor too.
Two copies of a security comparison is one more than there should be -- when
they drift, one side authorises and the other does not, and the failure looks
like a sandbox bug rather than a runner bug. ``kali_sandbox`` keeps its own copy
because the services ship separately; both are pinned to the same vectors in
their respective ``test_grant`` suites.
"""
from urllib.parse import urlparse

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

# A port claim wider than this is refused on the runner side too, not just in the
# sandbox. nmap's own default is "1-1000"; past a few thousand the claim has
# stopped describing a decision anyone made and become a licence for the whole
# host, which is the thing binding the port was meant to prevent. Checking on
# both sides means an over-wide claim is refused at mint time with a clear
# reason rather than at the gate with a 403 nobody can act on.
MAX_CLAIMED_PORTS = 4096


class PortClaimError(ValueError):
    """A port claim is malformed or too wide. Refuse rather than guess."""


def normalize_port_claim(claim) -> list:
    """Expand ``80``, ``"80,443"`` or ``"1-1000"`` to a sorted list of ints.

    Raises PortClaimError on anything malformed. The sandbox has the same
    function with the same rules; both are pinned to the same vectors in
    ``tests/test_grant_port_claim.py`` so the two cannot drift, because a claim
    the runner considered valid but the sandbox did not would fail as a 403
    after the runner had already spent its rate-limit budget.
    """
    if isinstance(claim, (list, tuple, set)):
        parts = [str(p) for p in claim]
    elif isinstance(claim, int) and not isinstance(claim, bool):
        parts = [str(claim)]
    elif isinstance(claim, str):
        parts = claim.split(",")
    else:
        raise PortClaimError(f"port claim {claim!r} is not a port or a spec")

    ports: set = set()
    for part in parts:
        part = part.strip()
        if not part:
            raise PortClaimError("port claim has an empty element")
        if "-" in part:
            lo_raw, _, hi_raw = part.partition("-")
            if not (lo_raw.strip().isdigit() and hi_raw.strip().isdigit()):
                raise PortClaimError(f"port range {part!r} is malformed")
            lo, hi = int(lo_raw), int(hi_raw)
            if lo > hi:
                raise PortClaimError(f"port range {part!r} is inverted")
            if not (1 <= lo <= 65535 and 1 <= hi <= 65535):
                raise PortClaimError(f"port range {part!r} is outside 1-65535")
            if hi - lo + 1 > MAX_CLAIMED_PORTS:
                raise PortClaimError(
                    f"port claim covers {hi - lo + 1} ports, more than the "
                    f"{MAX_CLAIMED_PORTS} this gate will honour"
                )
            ports.update(range(lo, hi + 1))
        else:
            if not part.isdigit():
                raise PortClaimError(f"port {part!r} is malformed")
            value = int(part)
            if not 1 <= value <= 65535:
                raise PortClaimError(f"port {value} is outside 1-65535")
            ports.add(value)

    if not ports:
        raise PortClaimError("port claim names no ports")
    return sorted(ports)


def ports_from_spec(spec: str) -> list:
    """The ports a target's own port specification names.

    A target may embed its ports the way the tool will read them
    (``juice_shop:3000``) or carry them in a separate field (nmap's ``ports``).
    Either way the set is the union, so a target naming two ports is authorised
    for both and no more.
    """
    candidate = (spec or "").strip()
    if not candidate:
        return []
    _, sep, port = candidate.rpartition(":")
    if not sep or not port.isdigit():
        return []
    return normalize_port_claim(int(port))


def authority_of(url: str) -> str:
    """Return ``host:port`` for a destination, with the scheme default filled in.

    Accepts both a bare ``host``/``host:port`` and a full URL. Returns ``""``
    when no host can be read, which every caller treats as "refuse".
    """
    candidate = (url or "").strip()
    if "://" not in candidate:
        candidate = "http://" + candidate
    try:
        parsed = urlparse(candidate)
        host = (parsed.hostname or "").lower()
        port = parsed.port
    except ValueError:
        # Out-of-range or otherwise unparseable port. Not a host we can reason
        # about, so no authority -- a caller must not get "" and read it as
        # "any port".
        return ""
    if not host:
        return ""
    if port is None:
        port = DEFAULT_PORTS.get((parsed.scheme or "").lower())
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return f"{host}:{port}" if port else host