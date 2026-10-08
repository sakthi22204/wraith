from pydantic import BaseModel
from typing import List, Optional, Any

class NmapPort(BaseModel):
    port: int
    protocol: str
    state: str
    service: Optional[str] = None
    version: Optional[str] = None

class NmapResult(BaseModel):
    target: str
    ports: List[NmapPort]
    raw_output: Optional[str] = None

class NucleiFinding(BaseModel):
    template_id: str
    info: dict
    type: str
    host: str
    matched_at: str
    severity: str

class NucleiResult(BaseModel):
    findings: List[NucleiFinding]
    raw_output: Optional[str] = None

class SQLMapResult(BaseModel):
    target: str
    # None means "sqlmap never reached a verdict" -- a run that timed out, was
    # interrupted, or never started. It is deliberately distinct from False,
    # which is a completed scan that looked and found no injection. Collapsing
    # the two reports an infrastructure failure as a clean result for the
    # target, which is the worst possible way for this tool to be wrong.
    vulnerable: Optional[bool] = None
    inconclusive: bool = False
    vulns: List[dict] = []
    raw_output: Optional[str] = None

class HydraResult(BaseModel):
    target: str
    service: str
    valid_credentials: List[dict] = []
    raw_output: Optional[str] = None

class MetasploitModule(BaseModel):
    fullname: str
    name: str
    type: str
    rank: str
    description: Optional[str] = None

class MetasploitResult(BaseModel):
    module: str
    success: bool
    # True when msfconsole produced no output at all (timeout, missing binary),
    # so success=False means "the run never happened" rather than "the exploit
    # did not land". Without this the two are indistinguishable.
    inconclusive: bool = False
    session_info: Optional[dict] = None
    raw_output: Optional[str] = None

class ScannerResult(BaseModel):
    """The tri-state verdict shared by the Phase 1.9 web scanners.

    `findings` non-empty means the scanner printed its own positive signals.
    `inconclusive` means the scanner never reached a verdict at all -- a
    timeout, a missing binary, or an image without the tool -- which is
    deliberately distinct from "scanned clean", so an infrastructure failure is
    never read as a clean bill of health. Both empty and not inconclusive is
    the honest "it ran and found nothing it would report".
    """
    tool: str
    target: str
    findings: List[str] = []
    inconclusive: bool = False
    raw_output: Optional[str] = None
