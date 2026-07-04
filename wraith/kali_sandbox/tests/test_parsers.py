import pytest
import os
from mcp_servers.nmap_server import NmapServer
from mcp_servers.nuclei_server import NucleiServer

def test_nmap_parser():
    server = NmapServer()
    base_path = os.path.dirname(__file__)
    with open(os.path.join(base_path, "fixtures/nmap.txt"), "r") as f:
        stdout = f.read()
    result = server.parse_nmap_output("127.0.0.1", stdout)
    assert len(result.ports) == 2
    assert result.ports[0].port == 80
    assert result.ports[1].service == "ssl/http"

def test_nuclei_parser():
    server = NucleiServer()
    base_path = os.path.dirname(__file__)
    with open(os.path.join(base_path, "fixtures/nuclei.jsonl"), "r") as f:
        stdout = f.read()
    result = server.parse_nuclei_output(stdout)
    assert len(result.findings) == 2
    assert result.findings[0].severity == "info"
    assert result.findings[1].severity == "high"
