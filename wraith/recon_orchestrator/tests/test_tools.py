import pytest
from app.tools.subfinder import SubfinderTool
from app.tools.httpx_probe import HttpxProbeTool
from app.tools.katana import KatanaTool
from app.tools.naabu import NaabuTool
import os

def test_subfinder_parser():
    tool = SubfinderTool()
    base_path = os.path.dirname(__file__)
    with open(os.path.join(base_path, "fixtures/subfinder.jsonl"), "r") as f:
        output = f.read()
    results = tool.parse_output(output)
    assert len(results.hosts) == 2
    assert results.hosts[0].value == "sub1.example.com"

def test_httpx_parser():
    tool = HttpxProbeTool()
    base_path = os.path.dirname(__file__)
    with open(os.path.join(base_path, "fixtures/httpx.jsonl"), "r") as f:
        output = f.read()
    results = tool.parse_output(output)
    assert len(results.endpoints) == 2
    assert results.endpoints[1].url == "https://api.example.com"

def test_katana_parser():
    tool = KatanaTool()
    base_path = os.path.dirname(__file__)
    with open(os.path.join(base_path, "fixtures/katana.jsonl"), "r") as f:
        output = f.read()
    results = tool.parse_output(output)
    assert len(results.endpoints) == 2
    assert results.endpoints[0].url == "https://example.com/about"
    assert results.endpoints[1].method == "POST"

def test_naabu_parser():
    tool = NaabuTool()
    base_path = os.path.dirname(__file__)
    with open(os.path.join(base_path, "fixtures/naabu.jsonl"), "r") as f:
        output = f.read()
    results = tool.parse_output(output)
    assert len(results.ports) == 2
    assert results.ports[0].number == 80
    assert results.ports[1].number == 443


def test_naabu_parser_deduplicates_ports():
    tool = NaabuTool()
    output = '\n'.join([
        '{"host":"example.com","port":443}',
        '{"host":"EXAMPLE.COM","port":443}',
    ])

    results = tool.parse_output(output)

    assert len(results.ports) == 1
    assert results.ports[0].number == 443
