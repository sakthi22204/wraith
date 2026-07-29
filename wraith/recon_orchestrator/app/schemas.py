from pydantic import BaseModel, Field, AliasChoices, computed_field
from typing import List, Dict, Optional, Any
from enum import Enum

class ToolStatus(str, Enum):
    WAITING = "waiting"
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"
    RETRYING = "retrying"

class ReconRequest(BaseModel):
    investigation_id: str = Field(..., validation_alias=AliasChoices("investigation_id", "program_id"))
    domains: List[str]

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

class ToolResults(BaseModel):
    hosts: List[HostResult] = []
    ports: List[PortResult] = []
    endpoints: List[EndpointResult] = []

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
