"""A tool container's stderr must never be recorded as recon evidence.

Containers are spawned without separating stdout from stderr, so a tool's own
logfmt diagnostics arrive interleaved with its results. Parsers that treated
every non-empty line as a result turned a gau config warning into a Host in the
graph (``time="2026-10-02T07;``) and then into an endpoint assembled from the
middle of that same warning.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.tools.gau import GauTool  # noqa: E402
from app.tools.linkfinder import LinkfinderTool  # noqa: E402
from app.tools.waybackurls import WaybackurlsTool  # noqa: E402

# The exact merged output from a real gau run against developer.crypto.com.
POLLUTED_OUTPUT = "\n".join(
    [
        "http://developer.crypto.com/",
        'time="2026-10-02T07:21:59Z" level=warning msg="error reading config: '
        'Config file /root/.gau.toml not found, using default config"',
        "https://developer.crypto.com/.well-known/security.txt",
        'http://time="2026-10-02T07/time="2026-10-02T07:21:59Z" level=warning '
        'msg="error reading config: Config file /root/.gau.toml not found"',
    ]
)

RAW_URL_TOOLS = [GauTool, WaybackurlsTool]


@pytest.mark.parametrize("factory", RAW_URL_TOOLS)
class TestStderrIsNotAnEndpoint:
    def test_only_real_urls_become_endpoints(self, factory):
        urls = [
            e.url
            for e in factory().parse_output(POLLUTED_OUTPUT, "developer.crypto.com").endpoints
        ]
        assert urls == [
            "http://developer.crypto.com/",
            "https://developer.crypto.com/.well-known/security.txt",
        ]

    def test_a_warning_line_never_becomes_a_host(self, factory):
        # The regression that reached the graph: `time="2026-10-02T07;` as a Host.
        results = factory().parse_output(POLLUTED_OUTPUT, "developer.crypto.com")
        assert results.endpoints
        for endpoint in results.endpoints:
            assert "=" not in endpoint.url
            assert " " not in endpoint.url
            assert endpoint.host == "developer.crypto.com"


@pytest.mark.parametrize("factory", RAW_URL_TOOLS)
def test_genuine_urls_are_untouched(factory):
    output = "http://example.com/api/v1/users\nhttps://example.com/index.html"
    urls = [e.url for e in factory().parse_output(output, "example.com").endpoints]
    assert urls == [
        "http://example.com/api/v1/users",
        "https://example.com/index.html",
    ]


@pytest.mark.parametrize("factory", RAW_URL_TOOLS)
def test_an_off_target_host_is_still_kept(factory):
    # Attribution, not authorization, is this parser's job. The runner's scope
    # gate is what decides whether a host may actually be probed, so filtering
    # by the target domain here would hide real recon evidence.
    urls = [e.url for e in factory().parse_output("https://cdn.test/two", "example.com").endpoints]
    assert urls == ["https://cdn.test/two"]


@pytest.mark.parametrize("factory", RAW_URL_TOOLS)
def test_empty_output_is_not_an_error(factory):
    assert factory().parse_output("", "example.com").endpoints == []
    assert factory().parse_output("\n\n", "example.com").endpoints == []


class TestLinkfinderStderrIsNotAnEndpoint:
    """linkfinder reports bare paths, so its failure mode is a config path.

    The whole line must be a result. A substring search used to lift
    `/root/.gau.toml` out of a diagnostic and record it as an endpoint on the
    target, which is indistinguishable from real recon evidence downstream.
    """

    TOOL = LinkfinderTool()
    TARGET = "developer.crypto.com"

    def test_only_whole_path_or_url_lines_become_endpoints(self):
        output = "\n".join(
            [
                "/js/main.js",
                'time="2026-10-02T07:21:59Z" level=warning msg="error reading config: '
                'Config file /root/.gau.toml not found, using default config"',
                "/admin/config",
                "http://developer.crypto.com/api/config",
            ]
        )
        urls = [e.url for e in self.TOOL.parse_output(output, self.TARGET).endpoints]
        assert urls == [
            f"http://{self.TARGET}/js/main.js",
            f"http://{self.TARGET}/admin/config",
            f"http://{self.TARGET}/api/config",
        ]

    def test_a_config_path_in_a_warning_is_never_an_endpoint(self):
        warning = (
            'time="2026-10-02T07:21:59Z" level=warning msg="error reading config: '
            'Config file /root/.gau.toml not found, using default config"'
        )
        assert self.TOOL.parse_output(warning, self.TARGET).endpoints == []

    def test_a_diagnostic_line_never_yields_its_path(self):
        # Every realistic shape: prose around the path, and logfmt key=value.
        for noise in [
            "reading /etc/passwd",
            "failed to open /tmp/out: permission denied",
            "level=error path=/var/log/linkfinder.log",
            'msg="Config file /root/.gau.toml not found"',
        ]:
            assert self.TOOL.parse_output(noise, self.TARGET).endpoints == [], noise

    def test_a_lone_filesystem_path_is_indistinguishable_from_a_real_one(self):
        """Documents the residual limit rather than papering over it.

        `/root/.gau.toml` on a line by itself is lexically identical to a real
        `/admin/config`, and this parser sees only a merged stream. Rejecting
        it would mean guessing from the shape -- discarding real endpoints like
        `/v1.0/api` along with the noise, which is the worse failure. The fix
        is scoped to what is actually decidable: a path that arrives inside a
        diagnostic is no longer mined out of one.
        """
        (endpoint,) = self.TOOL.parse_output("/root/.gau.toml", self.TARGET).endpoints
        assert endpoint.url == f"http://{self.TARGET}/root/.gau.toml"

    def test_real_paths_and_urls_still_parse(self):
        output = "/js/main.js\n/admin/config\nhttp://example.com/api/config"
        urls = [e.url for e in self.TOOL.parse_output(output, self.TARGET).endpoints]
        assert urls == [
            f"http://{self.TARGET}/js/main.js",
            f"http://{self.TARGET}/admin/config",
            f"http://{self.TARGET}/api/config",
        ]

    def test_empty_output_is_not_an_error(self):
        assert self.TOOL.parse_output("", self.TARGET).endpoints == []
        assert self.TOOL.parse_output("\n\n", self.TARGET).endpoints == []
