"""Regression: _push_to_graph must resolve each distinct host exactly once.

A toom.de recon produced 53,922 endpoints across ~942 hosts. The previous
implementation called upsert_host once per endpoint, so ~53k of those calls
were redundant Cypher round-trips that dominated the run's wall-clock.
"""
import pytest

from app import orchestrator as orch
from app.schemas import ToolResults, HostResult, EndpointResult


class _FakeGraph:
    def __init__(self):
        self.host_calls = []
        self.endpoint_calls = []
        self.port_calls = []
        self._next = 0

    async def upsert_host(self, investigation_id, host: HostResult):
        self.host_calls.append(host.value)
        self._next += 1
        return {"id": f"host-{self._next}"}

    async def upsert_endpoint(self, host_id, endpoint):
        self.endpoint_calls.append((host_id, endpoint.url))

    async def upsert_port(self, host_id, port):
        self.port_calls.append((host_id, port))


@pytest.fixture
def fake_graph(monkeypatch):
    g = _FakeGraph()
    monkeypatch.setattr(orch, "graph_client", g)
    return g


def _endpoint(host, url):
    return EndpointResult(host=host, url=url, method="GET", source_tool="gau")


@pytest.mark.asyncio
async def test_host_upserted_once_per_distinct_host(fake_graph):
    endpoints = []
    for i in range(500):
        # 5 distinct hosts, 500 endpoints -> 5 upserts, not 500.
        endpoints.append(_endpoint(f"h{i % 5}.example", f"https://h{i % 5}.example/{i}"))

    results = ToolResults(
        hosts=[HostResult(value=f"h{i}.example", source_tool="subfinder") for i in range(5)],
        endpoints=endpoints,
    )

    await orch.ReconOrchestrator.__new__(orch.ReconOrchestrator)._push_to_graph(
        "inv-1", results)

    assert len(fake_graph.host_calls) == 5, (
        f"expected 5 host upserts for 5 distinct hosts, got "
        f"{len(fake_graph.host_calls)}")
    assert len(set(fake_graph.host_calls)) == 5
    assert len(fake_graph.endpoint_calls) == 500


@pytest.mark.asyncio
async def test_host_not_prelisted_still_upserted_once(fake_graph):
    # Hosts seen only via endpoints (absent from results.hosts) must still be
    # created, and exactly once each.
    endpoints = [_endpoint("only.example", f"https://only.example/{i}") for i in range(50)]
    results = ToolResults(hosts=[], endpoints=endpoints)

    await orch.ReconOrchestrator.__new__(orch.ReconOrchestrator)._push_to_graph(
        "inv-2", results)

    assert fake_graph.host_calls == ["only.example"]
    assert len(fake_graph.endpoint_calls) == 50


@pytest.mark.asyncio
async def test_endpoint_ids_point_at_correct_host(fake_graph):
    endpoints = [
        _endpoint("a.example", "https://a.example/1"),
        _endpoint("b.example", "https://b.example/2"),
        _endpoint("a.example", "https://a.example/3"),
    ]
    results = ToolResults(
        hosts=[HostResult(value="a.example", source_tool="subfinder"),
               HostResult(value="b.example", source_tool="subfinder")],
        endpoints=endpoints,
    )

    await orch.ReconOrchestrator.__new__(orch.ReconOrchestrator)._push_to_graph(
        "inv-3", results)

    # endpoint_calls stores (host_id, url); we want url -> host_id.
    mapping = {url: host_id for host_id, url in fake_graph.endpoint_calls}
    # a.example was upserted first (host-1), b.example second (host-2).
    assert mapping["https://a.example/1"] == mapping["https://a.example/3"]
    assert mapping["https://b.example/2"] != mapping["https://a.example/1"]
    assert len(fake_graph.host_calls) == 2