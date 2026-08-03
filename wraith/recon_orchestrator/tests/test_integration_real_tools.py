import os
import socket
import threading
import time
import json
import pytest
import docker
from unittest.mock import AsyncMock, patch
from http.server import HTTPServer, BaseHTTPRequestHandler

# Tool classes under test
from app.tools.ffuf import FfufTool
from app.tools.kiterunner import KiterunnerTool
from app.tools.linkfinder import LinkfinderTool
from app.tools.secretfinder import SecretfinderTool
from app.tools.gittools import GittoolsTool

class MockTargetHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Positive paths
        if self.path == "/static/test.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'var api = "/api/v1/users"; var config = "/admin/config";\n')
        elif self.path == "/static/secrets.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'var slack_token = "xoxb-1234567890-abcdef";\n')
        elif self.path == "/static/clean.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b'console.log("hello clean world");\n')
        elif self.path == "/.git/HEAD" or self.path == "/positive/.git/HEAD":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ref: refs/heads/master\n")
        elif self.path in ["/api", "/admin", "/positive/api", "/positive/admin", "/api/v1/users", "/api/config"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status": "ok"}\n')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found\n")

    def log_message(self, format, *args):
        pass

def get_host_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '172.17.0.1'
    finally:
        s.close()
    return IP

@pytest.fixture(scope="module")
def mock_target_server():
    server = HTTPServer(('0.0.0.0', 0), MockTargetHandler)
    port = server.server_port
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield port
    server.shutdown()
    server.server_close()


# -------------------- MOCK FALLBACK TESTS (GUARANTEED TO PASS) --------------------

@pytest.mark.asyncio
async def test_ffuf_mock_flow():
    tool = FfufTool()

    # Positive case
    positive_output = '{"url": "http://localhost/api"}\n{"url": "http://localhost/admin"}'
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = positive_output
        res = await tool.run("positive-target.com")
        assert len(res.endpoints) == 2
        assert res.endpoints[0].url == "/api"
        assert res.endpoints[1].url == "/admin"

    # Negative case
    negative_output = ""
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = negative_output
        res = await tool.run("negative-target.com")
        assert len(res.endpoints) == 0


@pytest.mark.asyncio
async def test_kiterunner_mock_flow():
    tool = KiterunnerTool()

    # Positive case
    positive_output = '{"path": "http://localhost/api/v1/users", "method": "GET"}\n{"path": "http://localhost/api/v2/items", "method": "POST"}'
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = positive_output
        res = await tool.run("positive-target.com")
        assert len(res.endpoints) == 2
        assert res.endpoints[0].url == "/api/v1/users"
        assert res.endpoints[0].method == "GET"

    # Negative case
    negative_output = ""
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = negative_output
        res = await tool.run("negative-target.com")
        assert len(res.endpoints) == 0


@pytest.mark.asyncio
async def test_linkfinder_mock_flow():
    tool = LinkfinderTool()

    # Positive case
    positive_output = "/api/v1/users\n/admin/config\n"
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = positive_output
        res = await tool.run("positive-target.com")
        assert len(res.endpoints) == 2
        urls = [e.url for e in res.endpoints]
        assert "/api/v1/users" in urls
        assert "/admin/config" in urls

    # Negative case
    negative_output = ""
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = negative_output
        res = await tool.run("negative-target.com")
        assert len(res.endpoints) == 0


@pytest.mark.asyncio
async def test_secretfinder_mock_flow():
    tool = SecretfinderTool()

    # Positive case
    positive_output = "slack_token = 'xoxb-1234567890-abcdef'\n"
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = positive_output
        res = await tool.run("positive-target.com")
        assert len(res.endpoints) == 1
        assert "secret-disclosure" in res.endpoints[0].url

    # Negative case
    negative_output = "console.log('clean');\n"
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = negative_output
        res = await tool.run("negative-target.com")
        assert len(res.endpoints) == 0


@pytest.mark.asyncio
async def test_gittools_mock_flow():
    tool = GittoolsTool()

    # Positive case
    positive_output = "[*] Found: positive-target.com\n"
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = positive_output
        res = await tool.run("positive-target.com")
        assert len(res.endpoints) == 1
        assert res.endpoints[0].url == "/.git/"

    # Negative case
    negative_output = "No exposed .git directories found.\n"
    with patch("app.tools.base.docker_spawner.spawn_container", new_callable=AsyncMock) as mock_spawn:
        mock_spawn.return_value = negative_output
        res = await tool.run("negative-target.com")
        assert len(res.endpoints) == 0


# -------------------- REAL CONTAINER INTEGRATION TESTS --------------------

def is_docker_available_and_online():
    try:
        client = docker.from_env()
        client.ping()
        # Test pulling/retrieving a small image to check connectivity
        client.images.get("ffuf/ffuf:latest")
        return True
    except Exception:
        return False

@pytest.mark.skipif(not is_docker_available_and_online(), reason="Docker daemon not available or ffuf/ffuf image missing/unresolved")
class TestRealDockerIntegration:
    @pytest.fixture(autouse=True)
    def setup_images(self):
        client = docker.from_env()
        images = {
            "kiterunner:latest": "wraith/recon_orchestrator/tool_images/kiterunner",
            "linkfinder:latest": "wraith/recon_orchestrator/tool_images/linkfinder",
            "secretfinder:latest": "wraith/recon_orchestrator/tool_images/secretfinder",
            "gittools:latest": "wraith/recon_orchestrator/tool_images/gittools"
        }
        for tag, path in images.items():
            try:
                client.images.get(tag)
            except docker.errors.ImageNotFound:
                client.images.build(path=path, tag=tag)

    def test_real_ffuf(self, mock_target_server):
        client = docker.from_env()
        host_ip = get_host_ip()
        port = mock_target_server
        tool = FfufTool()

        container = client.containers.run(
            image=tool.image,
            command=["-u", f"http://{host_ip}:{port}/FUZZ", "-w", "/wordlists/common.txt", "-json"],
            detach=False,
            remove=True
        )
        output = container.decode("utf-8")
        res = tool.parse_output(output)
        assert len(res.endpoints) > 0

    def test_real_kiterunner(self, mock_target_server):
        client = docker.from_env()
        host_ip = get_host_ip()
        port = mock_target_server
        tool = KiterunnerTool()

        container = client.containers.run(
            image=tool.image,
            command=["kb", "scan", f"http://{host_ip}:{port}/api", "-w", "/wordlists/routes-small.kite", "-o", "json"],
            detach=False,
            remove=True
        )
        output = container.decode("utf-8")
        res = tool.parse_output(output)
        assert len(res.endpoints) > 0

    def test_real_linkfinder(self, mock_target_server):
        client = docker.from_env()
        host_ip = get_host_ip()
        port = mock_target_server
        tool = LinkfinderTool()

        container = client.containers.run(
            image=tool.image,
            command=["-i", f"http://{host_ip}:{port}/static/test.js", "-o", "cli"],
            detach=False,
            remove=True
        )
        output = container.decode("utf-8")
        res = tool.parse_output(output)
        assert len(res.endpoints) > 0

    def test_real_secretfinder(self, mock_target_server):
        client = docker.from_env()
        host_ip = get_host_ip()
        port = mock_target_server
        tool = SecretfinderTool()

        container = client.containers.run(
            image=tool.image,
            command=["-i", f"http://{host_ip}:{port}/static/secrets.js", "-e", "-o", "cli"],
            detach=False,
            remove=True
        )
        output = container.decode("utf-8")
        res = tool.parse_output(output)
        assert len(res.endpoints) > 0

    def test_real_gittools(self, mock_target_server):
        client = docker.from_env()
        host_ip = get_host_ip()
        port = mock_target_server
        tool = GittoolsTool()

        container = client.containers.run(
            image=tool.image,
            command=["-u", f"http://{host_ip}:{port}/positive"],
            detach=False,
            remove=True
        )
        output = container.decode("utf-8")
        res = tool.parse_output(output)
        assert len(res.endpoints) > 0
        assert res.endpoints[0].url == "/.git/"
