import enum
import json
from typing import List, Optional
from .common.base_server import BaseSecurityServer
from .common.parsers import NucleiResult, NucleiFinding

class NucleiTemplateCategory(str, enum.Enum):
    CVES = "cves"
    EXPOSURES = "exposures"
    VULNERABILITIES = "vulnerabilities"
    MISCONFIGURATION = "misconfiguration"
    DEFAULT = "default"

class NucleiServer(BaseSecurityServer):
    def __init__(self):
        super().__init__("Nuclei Server")
        self.setup_tools()

    def setup_tools(self):
        @self.mcp.tool()
        async def run_nuclei_scan(target: str, category: str = "default", caller: Optional[str] = None) -> NucleiResult:
            """Run a Nuclei scan against a target.

            category must be one of: default (all http templates), cves,
            exposures, vulnerabilities, misconfiguration. Use "default" unless
            you are looking for a specific class of issue.
            """
            self.verify_caller("run_nuclei_scan", caller)
            self.validate_target(target)

            # Use -json-export to get structured output
            # -dc (disable clustering) is mandatory here: nuclei's request clustering
            # collapsed 4371 http templates into 278 clusters / 237 requests and lost
            # every match, reporting 0 findings on a known-vulnerable target. The same
            # scan with -dc returns its findings. Do not remove without re-verifying.
            cmd = ["nuclei", "-u", target, "-jsonl", "-silent", "-dc", "-c", "15", "-timeout", "5"]
            if category != NucleiTemplateCategory.DEFAULT:
                # Nuclei v3+ templates are organized under protocol dirs (e.g. http/cves).
                category = category.value if hasattr(category, "value") else category
                try:
                    NucleiTemplateCategory(category)
                except ValueError:
                    return NucleiResult(
                        findings=[],
                        raw_output=f"Invalid category '{category}'. Allowed: default, cves, exposures, vulnerabilities, misconfiguration.",
                    )
                cmd.extend(["-t", f"http/{category}"])

            res = await self.run_tool(cmd, timeout=600)

            if not res.get("success") and not res.get("stdout"):
                return NucleiResult(findings=[], raw_output=res.get("error") or res.get("stderr") or "Nuclei scan produced no output.")

            return self.parse_nuclei_output(res.get("stdout", ""))

    def parse_nuclei_output(self, stdout: str) -> NucleiResult:
        findings = []
        for line in stdout.strip().split("\n"):
            if not line:
                continue
            try:
                data = json.loads(line)
                findings.append(NucleiFinding(
                    template_id=data.get("template-id"),
                    info=data.get("info", {}),
                    type=data.get("type"),
                    host=data.get("host"),
                    matched_at=data.get("matched-at"),
                    severity=data.get("info", {}).get("severity", "unknown")
                ))
            except json.JSONDecodeError:
                continue
        return NucleiResult(findings=findings, raw_output=stdout)

if __name__ == "__main__":
    server = NucleiServer()
    server.mcp.run()
