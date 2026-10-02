import pytest
from app.tools.dnsx import DnsxTool
from app.tools.tlsx import TlsxTool
from app.tools.gau import GauTool
from app.tools.waybackurls import WaybackurlsTool
from app.tools.cloud_enum import CloudEnumTool
from app.tools.nmap import NmapTool
from app.tools.ffuf import FfufTool
from app.tools.kiterunner import KiterunnerTool
from app.tools.wpscan import WpscanTool
from app.tools.httpx_probe import HttpxProbeTool
from app.tools.katana import KatanaTool


def test_web_tools_add_http_scheme_for_host_port_targets():
    assert HttpxProbeTool().get_command("juice_shop:3000")[1] == "http://juice_shop:3000"
    assert KatanaTool().get_command("juice_shop:3000")[1] == "http://juice_shop:3000"
from app.tools.linkfinder import LinkfinderTool
from app.tools.secretfinder import SecretfinderTool
from app.tools.trufflehog import TrufflehogTool
from app.tools.gittools import GittoolsTool

def test_dnsx_parser():
    tool = DnsxTool()
    output = '{"host": "sub.example.com", "name": "sub.example.com"}\n{"host": "api.example.com"}'
    res = tool.parse_output(output)
    assert len(res.hosts) == 2
    assert res.hosts[0].value == "sub.example.com"
    assert res.hosts[0].source_tool == "dnsx"

def test_tlsx_parser():
    tool = TlsxTool()
    output = '{"host": "example.com", "subject-dn": "CN=example.com"}'
    res = tool.parse_output(output)
    assert len(res.hosts) == 1
    assert res.hosts[0].value == "example.com"

def test_gau_parser():
    tool = GauTool()
    output = 'http://example.com/api/v1/users\nhttps://example.com/index.html'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 2
    # The URL is kept whole: a path alone is not something a later stage can
    # scope, probe or attribute to a target.
    assert res.endpoints[0].url == "http://example.com/api/v1/users"
    assert res.endpoints[1].url == "https://example.com/index.html"

def test_waybackurls_parser():
    tool = WaybackurlsTool()
    output = 'http://example.com/blog/posts\nhttps://example.com/wp-login.php'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 2
    assert res.endpoints[0].url == "http://example.com/blog/posts"

def test_cloud_enum_parser():
    tool = CloudEnumTool()
    output = 'OPEN: s3.amazonaws.com/example-bucket-found\nMUTATION: example-storage.blob.core.windows.net'
    res = tool.parse_output(output)
    assert len(res.hosts) == 2
    assert "s3.amazonaws.com" in res.hosts[0].value

def test_nmap_parser():
    tool = NmapTool()
    output = '80/tcp open http\n443/tcp open https'
    res = tool.parse_output(output, "example.com")
    assert len(res.ports) == 2
    assert res.ports[0].number == 80
    assert res.ports[1].number == 443
    # nmap prints no host of its own, so the scanned target is the only
    # attribution available and "unknown" would be a fabricated node.
    assert {p.host for p in res.ports} == {"example.com"}

def test_ffuf_parser():
    tool = FfufTool()
    output = '{"url": "http://example.com/secret"}\n{"url": "http://example.com/admin"}'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 2
    assert res.endpoints[0].url == "http://example.com/secret"

def test_kiterunner_parser():
    tool = KiterunnerTool()
    output = '{"path": "http://example.com/api/v2/items", "method": "POST"}'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 1
    assert res.endpoints[0].url == "http://example.com/api/v2/items"
    assert res.endpoints[0].method == "POST"

def test_kiterunner_parser_reanchors_a_relative_path():
    """kiterunner reports paths relative to its scan root, not whole URLs."""
    tool = KiterunnerTool()
    res = tool.parse_output('{"path": "/api/Users"}', "example.com")
    assert res.endpoints[0].url == "http://example.com/api/Users"

def test_wpscan_parser():
    tool = WpscanTool()
    output = '{"plugins": {"akismet": {}}, "themes": {"twentytwenty": {}}}'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 2
    assert "akismet" in res.endpoints[0].url
    assert res.endpoints[0].url.startswith("http://example.com/")

def test_linkfinder_parser():
    tool = LinkfinderTool()
    output = '/js/main.js\nhttp://example.com/api/config'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 2
    assert res.endpoints[0].url == "http://example.com/js/main.js"

def test_secretfinder_parser():
    tool = SecretfinderTool()
    # Real `-o cli` output, not the old "Found token: ..." invention.
    output = (
        "[ + ] URL: http://example.com/js/app.js\n"
        "slack_token\t->\txoxb-1234567890-abcdef\n"
    )
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 1
    assert res.endpoints[0].url == "http://example.com/js/app.js"
    assert "slack_token" in " ".join(res.notes)
    assert "xoxb-1234567890-abcdef" not in " ".join(res.notes)

def test_trufflehog_parser():
    tool = TrufflehogTool()
    output = 'Found private key leak in commit 123456'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 1
    assert "trufflehog-finding" in res.endpoints[0].url
    assert res.endpoints[0].url.startswith("http://example.com/")

def test_gittools_parser():
    tool = GittoolsTool()
    output = 'Exposed .git directory found!'
    res = tool.parse_output(output, "example.com")
    assert len(res.endpoints) == 1
    assert res.endpoints[0].url == "http://example.com/.git/"
