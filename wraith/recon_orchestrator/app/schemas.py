from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any
from enum import Enum

class ToolStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    TIMED_OUT = "timed_out"
    FAILED = "failed"

class ReconRequest(BaseModel):
    program_id: str
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
    program_id: str
    status: str
    tool_statuses: Dict[str, ToolStatus]
    progress: float

class ReconSessionResults(BaseModel):
    session_id: str
    results: ToolResults
