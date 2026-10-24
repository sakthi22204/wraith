from pydantic import BaseModel, Field, AliasChoices, computed_field
from typing import List, Dict, Optional, Any
from enum import Enum

class ToolStatus(str, Enum):
    WAITING = "waiting"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    RETRYING = "retrying"

class ReconRequest(BaseModel):
    investigation_id: str = Field(..., validation_alias=AliasChoices("investigation_id", "program_id"))
    domains: List[str]
    tools: Optional[List[str]] = None

class HostResult(BaseModel):
    value: str
    source_tool: str

class PortResult(BaseModel):
    host: str
    number: int
    protocol: str
    state: str
    source_tool: str

class EndpointResult(BaseModel):
    host: str
    url: str
    method: str
    source_tool: str

class FindingResult(BaseModel):
    """A vulnerability match a scanner reported at an endpoint.

    Kept separate from EndpointResult: the endpoint is the asset, the finding is
    the issue. Before this, nuclei's matches were folded into ``notes`` and the
    graph held an Endpoint but no Finding, so the investigation's findings list
    came back empty on an application the scanner had flagged.
    """
    host: str
    url: str
    method: str
    source_tool: str
    vuln_type: str
    severity: str
    title: str
    description: str = ""
    template_id: str = ""
    evidence: Optional[str] = None

class ToolResults(BaseModel):
    hosts: List[HostResult] = []
    ports: List[PortResult] = []
    endpoints: List[EndpointResult] = []
    findings: List[FindingResult] = []
    # Caveats about this tool's own output: what was filtered out and why.
    # Without somewhere to put them, a parser that discards results has to do
    # it silently, and "fuzzed, found nothing" is indistinguishable from
    # "never ran".
    notes: List[str] = []
    # How the container exited. A deadline stop means the scan ran and was
    # cut off -- keep the partial output, do not retry the same budget. An
    # OOM kill means the same command against the same limit fails again.
    # Both are set by ReconTool.run from the spawner's abort exceptions, so
    # the orchestrator can decide without inspecting logs.
    timed_out: bool = False
    oom_killed: bool = False

class ReconSessionStatus(BaseModel):
    session_id: str
    investigation_id: str = Field(..., validation_alias=AliasChoices("investigation_id", "program_id"))
    status: str
    tool_statuses: Dict[str, ToolStatus]
    progress: float
    current_tool: Optional[str] = None
    logs: List[str] = []

    @computed_field
    @property
    def program_id(self) -> str:
        return self.investigation_id

class ReconSessionResults(BaseModel):
    session_id: str
    results: ToolResults
