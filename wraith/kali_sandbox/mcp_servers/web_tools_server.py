"""Phase 1.9 scanner toolkit: eight web scanners exposed as gated MCP tools.

Each tool follows the same contract as sqlmap/nuclei in this stack:

- `verify_caller` + `validate_url` before anything runs;
- one fixed `argv` list passed to `create_subprocess_exec` (no shell, so no
  argument can become a second command);
- a tri-state verdict (`ScannerResult`): findings non-empty when the scanner
  prints its own positive signals, `inconclusive=True` when it produced no
  output at all (timeout, missing binary, tool absent from the image), and
  otherwise a clean "it ran and reported nothing".

A scanner's own conclusion markers decide the verdict; `res["success"]` is
never consulted for the negative direction, for the same reason sqlmap's is
not -- a tool can exit non-zero while still printing a complete clean result.
"""

import re
from typing import List, Optional, Tuple

from .common.base_server import BaseSecurityServer
from .common.parsers import ScannerResult

ARJUN_TIMEOUT_SECONDS = 300
DALFOX_TIMEOUT_SECONDS = 300
CORSY_TIMEOUT_SECONDS = 180
COMMIX_TIMEOUT_SECONDS = 300
GHAURI_TIMEOUT_SECONDS = 600
JWT_TIMEOUT_SECONDS = 180
NIKTO_TIMEOUT_SECONDS = 330
XSSTRIKE_TIMEOUT_SECONDS = 240

# Paths of the git-installed tools. Apt-installed tools (arjun, dalfox, commix,
# nikto, xsstrike) are on PATH.
CORSY_SCRIPT = "/opt/Corsy/corsy.py"
JWT_SCRIPT = "/opt/jwt_tool/jwt_tool.py"


# --- parsers ----------------------------------------------------------------
# Each takes the merged stdout+stderr of a completed run and returns the lines
# the scanner itself marked as findings. Kept module-level so the tri-state
# contract is unit-testable without spawning a scanner.

def parse_arjun(combined: str) -> List[str]:
    """Arjun's parameter conclusions.

    Versions disagree on word order (`Found parameters: a, b` vs
    `Parameters found: a, b`) and the per-parameter line carries the source
    Arjun inferred from (`parameter detected: q, based on: http headers`). The
    per-parameter lines are the more useful finding, so they win; the summary
    is the fallback for output that only carries a list.
    """
    detected = [
        f"parameter detected: {m.group(1).strip().strip(',')} "
        f"(based on: {m.group(2).strip()})"
        for m in re.finditer(
            r"parameter detected:\s*([^,\n]+),\s*based on:\s*([^|\n]+)",
            combined, re.IGNORECASE)
    ]
    if detected:
        return detected
    findings = []
    for match in re.finditer(
            r"(?:Found parameters|Parameters found):\s*(.+)$",
            combined, re.IGNORECASE | re.MULTILINE):
        findings.append(f"parameters: {match.group(1).strip()}")
    return findings


def parse_dalfox(combined: str) -> List[str]:
    """Dalfox prints each PoC/verdict line with `[P]`/`[K]`/`[C]`/`[!]`."""
    return [
        line.strip() for line in combined.splitlines()
        if re.match(r"^\[[PKC!]\]", line.strip())
    ]


_CORSY_HEADER_RE = re.compile(
    r"(access-control-allow|acao\s+header|acac\s+header)", re.IGNORECASE)


def parse_corsy(combined: str) -> List[str]:
    """Corsy surfaces the response ACAO/ACAC headers it considers misconfigured.

    Corsy's own report renders the pair as ``ACAO Header:`` / ``ACAC Header:``
    rather than the raw header names, so both spellings are accepted.
    """
    return [
        line.strip() for line in combined.splitlines()
        if _CORSY_HEADER_RE.search(line)
    ]


# commix's wording depends on the version: older output pairs
# `(vulnerable)` / `(not vulnerable)` with its own conclusion, current (4.x)
# prints "does not seem to be injectable" / "do not appear to be injectable"
# instead. Both spellings are the tool's verdict; anything else (a banner, a
# prompt it could not answer) is not.
COMMIX_NOT_MARKERS = (
    "(not vulnerable)",
    "does not seem to be injectable",
    "do not appear to be injectable",
    "might not be injectable",
)
COMMIX_VULNERABLE_MARKERS = (
    "(vulnerable)",
    "seems to be injectable",
    "appears to be injectable",
)


def parse_commix(combined: str) -> List[str]:
    """Commix's own conclusion, in either the legacy or 4.x phrasing."""
    if any(marker in combined for marker in COMMIX_NOT_MARKERS):
        return []
    if any(marker in combined for marker in COMMIX_VULNERABLE_MARKERS):
        return ["the parameter is vulnerable to OS command injection"]
    return []


GHAURI_NOT_MARKERS = ("not vulnerable", "not injectable", "does not appear")
GHAURI_VULN_MARKERS = ("appears to be injectable", "is vulnerable")


def parse_ghauri(combined: str) -> List[str]:
    """Not-checked first: 'not vulnerable' must not be read as a positive."""
    if any(marker in combined for marker in GHAURI_NOT_MARKERS):
        return []
    if any(marker in combined for marker in GHAURI_VULN_MARKERS):
        return ["the parameter appears to be injectable (SQL injection)"]
    return []


def parse_jwt_tool(combined: str) -> List[str]:
    """jwt_tool's decoded header/payload blocks plus exploit and alert lines."""
    findings: List[str] = []
    capture = False
    for line in combined.splitlines():
        stripped = line.strip()
        if not stripped:
            if capture:
                capture = False
            continue
        if stripped.startswith("*** Decoded") or stripped.startswith("Decoded Token Values"):
            capture = True
            continue
        if capture:
            findings.append(stripped)
            continue
        low = stripped.lower()
        if stripped.startswith("jwttool_") or "exploit:" in low:
            findings.append(stripped)
            continue
        if "[!]" in stripped or "success" in low or "vulnerab" in low:
            findings.append(stripped)
    seen: set = set()
    return [f for f in findings if not (f in seen or seen.add(f))]


def parse_nikto(combined: str) -> List[str]:
    """Every `+ ` line nikto prints is an observation/finding."""
    return [
        match.group(1).strip()
        for match in re.finditer(r"^\+\s*(.+)$", combined, re.MULTILINE)
        if match.group(1).strip()
    ]


XSSTRIKE_FINDING_RE = re.compile(
    r"^\[\+\]\s*(.*(?:[Rr]eflected|script|XSS|vulnerab|[Ii]njection).*)$",
    re.MULTILINE)


def parse_xsstrike(combined: str) -> List[str]:
    return [match.group(1).strip() for match in XSSTRIKE_FINDING_RE.finditer(combined)]


class WebToolsServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("Web Tools Server")
        self.setup_tools()

    async def _scan(self, tool: str, target: str, cmd: List[str],
                    timeout: int, parser, verdict: Optional[Tuple[str, ...]] = None
                    ) -> ScannerResult:
        """Run a scanner and turn its output into findings.

        ``verdict`` names the strings that constitute the tool's own
        conclusion. A scanner that starts, prints its banner and then bails out
        (a prompt it could not answer, a target it refused) still writes to
        stdout; without this it would be parsed into ``findings=[]`` and read as
        a clean result. When none of the verdict markers are present the run is
        reported as inconclusive instead, which callers already treat as "no
        usable verdict" rather than "nothing found".
        """
        res = await self.run_tool(cmd, timeout=timeout)
        stdout = res.get("stdout") or ""
        combined = stdout + "\n" + (res.get("stderr") or "")
        if not stdout.strip():
            return ScannerResult(
                tool=tool, target=target, findings=[], inconclusive=True,
                raw_output=(
                    res.get("error")
                    or res.get("stderr")
                    or f"{tool} produced no output, so it reached no verdict."
                ),
            )
        findings = parser(combined)
        reached_verdict = (verdict is None
                           or any(marker in combined for marker in verdict))
        return ScannerResult(
            tool=tool, target=target, findings=findings,
            inconclusive=not reached_verdict, raw_output=stdout,
        )

    def setup_tools(self):
        @self.mcp.tool()
        async def run_arjun(url: str, caller: Optional[str] = None) -> ScannerResult:
            """Discover URL/body parameters with Arjun.

            Arjun fuzzes parameter names against the target URL and reports the
            ones the endpoint accepts. Parameter discovery is a finding, not a
            vulnerability; use the result to learn what inputs the endpoint
            processes. Gated on scope and a signed grant before anything runs.
            """
            self.verify_caller("run_arjun", caller)
            self.validate_url(url)
            return await self._scan(
                "arjun", url, ["arjun", "-u", url], ARJUN_TIMEOUT_SECONDS,
                parse_arjun,
                verdict=("Parameters found:", "Found parameters:",
                         "No parameters were discovered", "parameter detected:"))

        @self.mcp.tool()
        async def run_dalfox(url: str, caller: Optional[str] = None) -> ScannerResult:
            """Scan a URL for XSS with Dalfox.

            Dalfox runs its XSS payload battery against the URL and reports each
            verified reflection/PoC. Gated on scope and a signed grant; this is
            an automated XSS scanner, so use only on targets you are authorized
            to inject into.
            """
            self.verify_caller("run_dalfox", caller)
            self.validate_url(url)
            return await self._scan(
                "dalfox", url,
                ["dalfox", "scan", url, "--no-color"],
                DALFOX_TIMEOUT_SECONDS, parse_dalfox)

        @self.mcp.tool()
        async def run_corsy(url: str, caller: Optional[str] = None) -> ScannerResult:
            """Check a target's CORS policy with Corsy.

            The finding lines are the `Access-Control-Allow-Origin` /
            `-Credentials` headers Corsy saw on the response; grade the policy
            from those, e.g. a reflected origin paired with credentials. Gated
            on scope and a signed grant.
            """
            self.verify_caller("run_corsy", caller)
            self.validate_url(url)
            return await self._scan(
                "corsy", url, ["python3", CORSY_SCRIPT, "-u", url],
                CORSY_TIMEOUT_SECONDS, parse_corsy)

        @self.mcp.tool()
        async def run_commix(url: str, param: Optional[str] = None,
                             method: str = "GET", data: Optional[str] = None,
                             caller: Optional[str] = None) -> ScannerResult:
            """Test a URL/parameter for OS command injection with Commix.

            Uses Commix's own `(vulnerable)` / `(not vulnerable)` conclusion.
            Gated on scope and a signed grant; only run against targets you are
            authorized to test for command injection.
            """
            self.verify_caller("run_commix", caller)
            self.validate_url(url)
            # commix treats any non-TTY stdin as a target list and silently
            # ignores -u, so a piped invocation would exit after its banner with
            # no tests run. --ignore-stdin forces URL mode. The answer override
            # is the other silent bail-out: the target answers 500 to the
            # heuristic probe and commix's batch default is to skip the rest of
            # the scan, which would otherwise read as "not vulnerable".
            cmd = ["commix", "--url", url, "--batch", "--level=1",
                   "--ignore-stdin",
                   "--answers=ignore HTTP response code=Y"]
            if param:
                cmd.extend(["-p", param])
            if method != "GET":
                cmd.extend(["--method", method])
            if data:
                cmd.extend(["--data", data])
            return await self._scan(
                "commix", url, cmd, COMMIX_TIMEOUT_SECONDS, parse_commix,
                verdict=COMMIX_VULNERABLE_MARKERS + COMMIX_NOT_MARKERS)

        @self.mcp.tool()
        async def run_ghauri(url: str, param: Optional[str] = None,
                             method: str = "GET", data: Optional[str] = None,
                             caller: Optional[str] = None) -> ScannerResult:
            """Test a URL/parameter for SQL injection with Ghauri.

            Injected-only verification by default (`--smart` is deliberately
            not passed so ghauri behaves like the batch tools beside it).
            Gated on scope and a signed grant; only run against targets you are
            authorized to test.
            """
            self.verify_caller("run_ghauri", caller)
            self.validate_url(url)
            cmd = ["ghauri", "-u", url, "--batch"]
            if param:
                cmd.extend(["-p", param])
            if method != "GET":
                cmd.extend(["--method", method])
            if data:
                cmd.extend(["--data", data])
            return await self._scan(
                "ghauri", url, cmd, GHAURI_TIMEOUT_SECONDS, parse_ghauri,
                verdict=GHAURI_NOT_MARKERS + GHAURI_VULN_MARKERS)

        @self.mcp.tool()
        async def run_jwt_tool(token: str, target: str, mode: str = "alg",
                               pubkey: Optional[str] = None,
                               caller: Optional[str] = None) -> ScannerResult:
            """Decode a JWT and test it against a target with jwt_tool.

            Always decodes the token (the header/payload blocks are returned as
            findings). With `target` set, tests the token's algorithm handling
            against that URL with the named mode: `alg` (alg:none forgery),
            `none` (null signature), `er` (forced-error scan), or `key`
            (RS256->HS256 key confusion, which needs `pubkey` as a PEM path).
            The token is echoed back in the Authorization header so jwt_tool can
            substitute the forged value, and the destination is gated on scope
            and a signed grant like every other network tool here.
            """
            self.verify_caller("run_jwt_tool", caller)
            if mode not in ("alg", "none", "er", "key"):
                raise ValueError(f"unsupported jwt mode '{mode}'")
            if mode == "key" and not pubkey:
                raise ValueError("jwt mode 'key' requires the target's public key PEM")
            self.validate_url(target)
            cmd = ["python3", JWT_SCRIPT, token]
            if mode == "er":
                cmd.extend(["-M", "er"])
            elif mode == "key":
                cmd.extend(["-X", "k", "-pk", pubkey])
            else:
                cmd.extend(["-X", {"alg": "a", "none": "n"}[mode]])
            cmd.extend(["-t", target, "-rh", f"Authorization: Bearer {token}"])
            return await self._scan(
                "jwt_tool", target, cmd, JWT_TIMEOUT_SECONDS, parse_jwt_tool)

        @self.mcp.tool()
        async def run_nikto(url: str, caller: Optional[str] = None) -> ScannerResult:
            """Web server scan with Nikto.

            Returns every `+` observation line (server header, interesting
            files, OSVDB items, CVEs). Can be slow; the run is capped with
            `-maxtime` and the verdict is tri-state like the other scanners.
            Gated on scope and a signed grant.
            """
            self.verify_caller("run_nikto", caller)
            self.validate_url(url)
            return await self._scan(
                "nikto", url,
                ["nikto", "-h", url, "-nointeractive", "-maxtime", "300s"],
                NIKTO_TIMEOUT_SECONDS, parse_nikto)

        @self.mcp.tool()
        async def run_xsstrike(url: str, data: Optional[str] = None,
                               caller: Optional[str] = None) -> ScannerResult:
            """Test a URL for reflected XSS with XSStrike.

            XSStrike's `[+]` reflection/scripting lines are the findings; the
            `--skip` flag answers its "continue?" prompt non-interactively so
            the run stays bounded. Gated on scope and a signed grant; only run
            against targets you are authorized to inject into.
            """
            self.verify_caller("run_xsstrike", caller)
            self.validate_url(url)
            cmd = ["xsstrike", "-u", url, "--skip"]
            if data:
                cmd.extend(["--data", data])
            return await self._scan("xsstrike", url, cmd,
                                    XSSTRIKE_TIMEOUT_SECONDS, parse_xsstrike)


if __name__ == "__main__":
    server = WebToolsServer()
    server.mcp.run()