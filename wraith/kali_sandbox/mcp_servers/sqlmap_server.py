import enum
from typing import List, Optional
from .common.base_server import BaseSecurityServer
from .common.parsers import SQLMapResult

class SQLMapMethod(str, enum.Enum):
    GET = "GET"
    POST = "POST"

# At --risk=2 --level=3 sqlmap walks a large technique/DBMS matrix per parameter
# and does not reach a verdict inside 10 minutes on ordinary targets, so the old
# 600s ceiling expired before it printed anything. Raising the ceiling is what
# lets the verdict path run at all; the inconclusive path below is what keeps a
# run that *still* times out from being read as a clean result.
SQLMAP_TIMEOUT_SECONDS = 1800

# sqlmap's own conclusion lines. Both directions are needed: the positive marker
# on its own cannot tell "found injection" apart from "scanned, found nothing",
# so a quiet run used to be reported as vulnerable=False.
SQLMAP_VULNERABLE_MARKERS = ("is vulnerable",)
SQLMAP_NOT_VULNERABLE_MARKERS = (
    "does not seem to be injectable",
    "do not appear to be injectable",
)

class SQLMapServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("SQLMap Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def run_sqlmap(url: str, param: Optional[str] = None, method: str = "GET", data: Optional[str] = None, caller: Optional[str] = None) -> SQLMapResult:
            """Run SQLMap against a target URL."""
            self.verify_caller("run_sqlmap", caller)
            self.validate_target(url)

            cmd = ["sqlmap", "-u", url, "--batch", "--risk=2", "--level=3"]
            if param:
                cmd.extend(["-p", param])
            if method == SQLMapMethod.POST:
                cmd.extend(["--method", "POST"])
            if data:
                cmd.extend(["--data", data])

            res = await self.run_tool(cmd, timeout=SQLMAP_TIMEOUT_SECONDS)
            stdout = res["stdout"]

            # A run that timed out, or never started because the binary is absent,
            # leaves stdout empty. Deciding "not vulnerable" from that would turn
            # an infrastructure failure into a clean bill of health, so the
            # verdict stays None and the caller is told the answer is unknown.
            if not stdout.strip():
                return SQLMapResult(
                    target=url,
                    vulnerable=None,
                    inconclusive=True,
                    raw_output=(
                        res.get("error")
                        or res.get("stderr")
                        or "sqlmap produced no output, so it reached no verdict."
                    ),
                )

            # Deliberately NOT gated on res["success"]: sqlmap reports "not
            # vulnerable" with a non-zero exit while still printing the evidence,
            # so exit status says nothing about whether a verdict was reached.
            if any(marker in stdout for marker in SQLMAP_VULNERABLE_MARKERS):
                vulnerable: Optional[bool] = True
            elif any(marker in stdout for marker in SQLMAP_NOT_VULNERABLE_MARKERS):
                vulnerable = False
            else:
                # Output exists but no conclusion was printed: killed mid-scan, or
                # truncated before the summary. Still not a clean bill of health.
                vulnerable = None

            return SQLMapResult(
                target=url,
                vulnerable=vulnerable,
                inconclusive=vulnerable is None,
                raw_output=stdout,
            )

if __name__ == "__main__":
    server = SQLMapServer()
    server.mcp.run()
