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
            """Run a Nuclei scan against a target."""
            self.verify_caller("run_nuclei_scan", caller)
            self.validate_target(target)

            # Use -json-export to get structured output
            cmd = ["nuclei", "-u", target, "-jsonl", "-silent"]
            if category != NucleiTemplateCategory.DEFAULT:
                # Nuclei v3+ templates are organized under protocol dirs (e.g. http/cves).
                category = category.value if hasattr(category, "value") else category
                cmd.extend(["-t", f"http/{category}"])

            res = await self.run_tool(cmd, timeout=600)

            if not res["success"] and not res["stdout"]:
                return NucleiResult(findings=[], raw_output=res.get("error") or res.get("stderr"))

            return self.parse_nuclei_output(res["stdout"])

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
