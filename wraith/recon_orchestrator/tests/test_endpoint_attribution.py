"""Tests that recon records endpoints as addresses a later stage can act on.

Every tool here has the same shape of bug available to it: the tool reports what
it matched as a path, the path is stored, and the host -- which the tool knew,
because it was just handed the target -- is dropped on the floor. Nothing
downstream fails. The endpoint simply stops existing as far as the pipeline is
concerned, because the hypothesis generator cannot scope a URL with no
authority and skips it.

So the assertion in this file is deliberately blunt: a recorded endpoint carries
a host. The specific URL shape is checked only where a tool legitimately reports
another origin.
"""
import json

import pytest

from app.tools.base import absolute_url, host_from_domain
from app.tools.ffuf import FfufTool
from app.tools.gau import GauTool
from app.tools.gittools import GittoolsTool
from app.tools.kiterunner import KiterunnerTool
from app.tools.linkfinder import LinkfinderTool
from app.tools.nmap import NmapTool
from app.tools.secretfinder import SecretfinderTool
from app.tools.trufflehog import TrufflehogTool
from app.tools.waybackurls import WaybackurlsTool
from app.tools.wpscan import WpscanTool


TARGET = "juice_shop:3000"


class TestAbsoluteUrl:
    @pytest.mark.parametrize("path,expected", [
        ("/login", "http://juice_shop:3000/login"),
        ("login", "http://juice_shop:3000/login"),
        ("http://juice_shop:3000/login", "http://juice_shop:3000/login"),
        ("https://other.test/x", "https://other.test/x"),
        ("//cdn.example.com/a.js", "http://cdn.example.com/a.js"),
    ])
    def test_the_authority_is_always_attached(self, path, expected):
        assert absolute_url(path, TARGET) == expected

    def test_a_path_with_no_target_is_left_alone(self):
        """Better a bare path, honestly bare, than a URL pointing at nothing."""
        assert absolute_url("/login", "") == "/login"

    def test_a_target_with_a_scheme_is_not_doubled(self):
        assert absolute_url("/x", "http://t.test") == "http://t.test/x"

    def test_a_trailing_slash_on_the_target_does_not_double(self):
        assert absolute_url("/x", "http://t.test/") == "http://t.test/x"

    def test_host_from_domain_strips_scheme_and_port(self):
        assert host_from_domain("http://t.test:8080/a") == "t.test"


class TestToolsKeepTheHost:
    """Each tool, fed its own kind of output, must record a scannable URL."""

    def test_ffuf_keeps_the_url_it_matched(self):
        output = "\n".join([
            json.dumps({"url": f"http://{TARGET}/admin", "status": 200}),
            json.dumps({"url": f"http://{TARGET}/api", "status": 200}),
        ])
        results = FfufTool().parse_output(output, TARGET)
        # The port lives in the URL, which is what gets scoped and probed. The
        # host field is the bare hostname, as every other tool reports it.
        assert [e.url for e in results.endpoints] == [
            f"http://{TARGET}/admin", f"http://{TARGET}/api"]
        assert {e.host for e in results.endpoints} == {"juice_shop"}

    def test_ffuf_does_not_invent_a_url_without_one(self):
        assert FfufTool().parse_output(json.dumps({"status": 404}), TARGET).endpoints == []

    def test_gau_keeps_the_whole_url(self):
        output = f"http://{TARGET}/one\nhttps://cdn.test/two\n"
        results = GauTool().parse_output(output, TARGET)
        assert [e.url for e in results.endpoints] == [
            f"http://{TARGET}/one", "https://cdn.test/two"]

    def test_waybackurls_keeps_the_whole_url(self):
        output = f"http://{TARGET}/old\n"
        results = WaybackurlsTool().parse_output(output, TARGET)
        assert results.endpoints[0].url == f"http://{TARGET}/old"

    def test_kiterunner_reanchors_a_scan_relative_path(self):
        output = "\n".join([
            json.dumps({"path": "/api/Users", "method": "GET"}),
            json.dumps({"url": f"http://{TARGET}/api/Products", "method": "POST"}),
        ])
        results = KiterunnerTool().parse_output(output, TARGET)
        assert [e.url for e in results.endpoints] == [
            f"http://{TARGET}/api/Users", f"http://{TARGET}/api/Products"]
        assert results.endpoints[1].method == "POST"

    def test_gittools_attributes_the_exposed_repo(self):
        # Finder's match line is the evidence; the banner around it is noise.
        results = GittoolsTool().parse_output(f"[*] Found: {TARGET}", TARGET)
        assert results.endpoints[0].url == f"http://{TARGET}/.git/"

    def test_gittools_reports_nothing_when_nothing_was_found(self):
        assert GittoolsTool().parse_output("no exposed git found", TARGET).endpoints == []

    def test_gittools_banner_is_not_a_finding(self):
        """The banner mentions "git" on every run, including runs that found
        nothing. Matching it invented `/.git/` on a dead port and sent nuclei
        into a 30-minute timeout against a service that was never listening."""
        banner = (
            "###########\n"
            "# Finder is part of https://github.com/internetwache/GitTools\n"
            "# Developed and maintained by @gehaxelt\n"
            "###########\n"
            "Scanning...\n"
            "Finished\n"
        )
        assert GittoolsTool().parse_output(banner, TARGET).endpoints == []

    def test_linkfinder_anchors_a_target_path(self):
        results = LinkfinderTool().parse_output("/assets/app.js\n", TARGET)
        assert results.endpoints[0].url == f"http://{TARGET}/assets/app.js"

    def test_secretfinder_attributes_its_marker(self):
        """A secret is attributed to the file it was found in.

        The tool used to synthesise `/secret-disclosure-secretfinder` and
        keyword-match whole lines, which meant a URL header mentioning
        `secrets.js` counted as a finding and a real `google_api` match -- whose
        name contains no "token", "key" or "secret" -- did not. Both directions
        were wrong: a phantom node on the graph for a file that was never
        compromised, and a genuine API key silently dropped.
        """
        results = SecretfinderTool().parse_output(
            "[ + ] URL: http://t.test/static/app.js\n"
            "google_api\t->\tAIzaSyBqK7mN2pL4xR8vT1yU3wZ5aC6dE9fG0h\n",
            TARGET,
        )
        assert [e.url for e in results.endpoints] == ["http://t.test/static/app.js"]
        assert results.endpoints[0].host == "t.test"
        assert results.endpoints[0].source_tool == "secretfinder"

    def test_secretfinder_does_not_report_a_filename_as_a_finding(self):
        """The false positive the keyword match produced.

        `secrets.js` contains the word "secret", so any line naming that file
        was counted as a discovery -- including the URL header that introduces
        the very block it belongs to.
        """
        results = SecretfinderTool().parse_output(
            "[ + ] URL: http://t.test/static/secrets.js\n"
            "console.log(1);\n",
            TARGET,
        )
        assert results.endpoints == [], "a filename was reported as a leaked secret"

    def test_secretfinder_reports_the_type_but_never_the_value(self):
        """A findings graph outlives the engagement; a live key in it is a liability.

        The note names the type and the file so the finding is actionable, and
        the value is left behind for whoever fetches the URL to confirm.
        """
        secret = "AIzaSyBqK7mN2pL4xR8vT1yU3wZ5aC6dE9fG0h"
        results = SecretfinderTool().parse_output(
            f"[ + ] URL: http://t.test/static/app.js\ngoogle_api\t->\t{secret}\n",
            TARGET,
        )
        assert results.notes, "the finding was not recorded at all"
        assert "google_api" in results.notes[0]
        assert "app.js" in results.notes[0]
        assert secret not in " ".join(results.notes)
        assert secret not in results.endpoints[0].model_dump_json()

    def test_secretfinder_attributes_each_block_to_its_own_file(self):
        """With -e the input is a page, so every linked JS file gets a block.

        Reporting every secret against the page URL would send an operator to
        the wrong file.
        """
        results = SecretfinderTool().parse_output(
            "[ + ] URL: http://t.test/\n"
            "[ + ] URL: http://t.test/static/a.js\n"
            "slack_token\t->\txoxb-1\n"
            "[ + ] URL: http://t.test/static/b.js\n"
            "google_api\t->\tAIza1\n",
            TARGET,
        )
        assert [e.url for e in results.endpoints] == [
            "http://t.test/static/a.js",
            "http://t.test/static/b.js",
        ]

    def test_secretfinder_dedupes_repeated_types_in_one_file(self):
        """The same key twice in one file is one thing to go and look at."""
        results = SecretfinderTool().parse_output(
            "[ + ] URL: http://t.test/static/app.js\n"
            "google_api\t->\tAIza1\n"
            "google_api\t->\tAIza2\n",
            TARGET,
        )
        assert len(results.endpoints) == 1

    def test_secretfinder_says_so_when_a_finding_cannot_be_attributed(self):
        """No header, no file, so nothing to attribute -- and no value kept.

        The alternative was synthesising a URL, which puts a node in the graph
        for something that does not exist on the target.
        """
        results = SecretfinderTool().parse_output("google_api\t->\tAIza1\n", TARGET)
        assert results.endpoints == []
        assert results.notes and "not attributable" in results.notes[0]
        assert "AIza1" not in " ".join(results.notes)

    def test_secretfinder_reports_nothing_when_nothing_was_found(self):
        """A block header with no findings under it is a clean scan."""
        results = SecretfinderTool().parse_output(
            "[ + ] URL: http://t.test/static/app.js\n", TARGET)
        assert results.endpoints == []
        assert results.notes == []

    def test_trufflehog_never_synthesises_a_url(self):
        """A banner line is not a detection, and a detection has no invented URL.

        The old parser substring-matched "found"/"leak"/"secret" anywhere in a
        line and emitted http://<domain>/trufflehog-finding for each hit. Those
        URLs do not exist, but they were persisted as assets and later proposed
        as validation candidates, so a finding could rest on a fabricated route.
        """
        results = TrufflehogTool().parse_output(
            "## Found 2 secret(s) in git http://juice_shop:3000\n"
            "Secret found in file config.py line 12\n",
            TARGET,
        )
        assert results.endpoints == []
        assert any("no endpoint was synthesised" in n for n in results.notes)

    def test_trufflehog_records_a_real_location_from_metadata_only(self):
        results = TrufflehogTool().parse_output(
            json.dumps({
                "SourceMetadata": {"Data": {"HTTP": {"URL": "https://api.toom.de/.env"}}},
                "DetectorName": "PrivateKey",
                "Verified": True,
                "Raw": "-----BEGIN PRIVATE KEY-----",
            }),
            TARGET,
        )
        assert [e.url for e in results.endpoints] == ["https://api.toom.de/.env"]
        assert results.endpoints[0].source_tool == "trufflehog"

    def test_trufflehog_never_persists_raw_secret_material(self):
        secret = "AKIAIOSFODNN7EXAMPLEKEY"
        results = TrufflehogTool().parse_output(
            json.dumps({
                "SourceMetadata": {"Data": {"Git": {"repository": "r", "file": "c.py"}}},
                "DetectorName": "AWS",
                "Verified": False,
                "Raw": secret,
            }),
            TARGET,
        )
        assert secret not in json.dumps(results.model_dump())
        assert any("detector=AWS verified=false" in n for n in results.notes)
        assert any("2 verified and 1 unverified" not in n for n in results.notes)

    def test_wpscan_attributes_plugins_and_themes(self):
        output = json.dumps({"plugins": {"akismet": {}}, "themes": {"twentytwenty": {}}})
        results = WpscanTool().parse_output(output, TARGET)
        assert [e.url for e in results.endpoints] == [
            f"http://{TARGET}/wp-content/plugins/akismet/",
            f"http://{TARGET}/wp-content/themes/twentytwenty/",
        ]

    def test_nmap_attributes_ports_to_the_scanned_target(self):
        """nmap prints no host, so dropping it created a literal 'unknown' node."""
        results = NmapTool().parse_output(
            "80/tcp open http\n443/tcp open https\n", TARGET)
        assert {p.host for p in results.ports} == {"juice_shop"}
        assert "unknown" not in {p.host for p in results.ports}
        assert {p.number for p in results.ports} == {80, 443}


class TestNoEndpointLacksAHost:
    """The invariant, checked against every endpoint-producing tool at once.

    A per-tool test can pass while a tool nobody remembered drops the host. This
    one fails if any tool regresses, including a new one added later.
    """

    CASES = [
        (FfufTool(), json.dumps({"url": f"http://{TARGET}/x"})),
        (GauTool(), f"http://{TARGET}/x"),
        (WaybackurlsTool(), f"http://{TARGET}/x"),
        (KiterunnerTool(), json.dumps({"path": "/x"})),
        (GittoolsTool(), f"[*] Found: {TARGET}"),
        (LinkfinderTool(), "/x"),
        (SecretfinderTool(), f"[ + ] URL: http://{TARGET}/static/app.js\ngoogle_api\t->\tAIza1\n"),
        (TrufflehogTool(), json.dumps({
            "SourceMetadata": {"Data": {"HTTP": {"URL": "https://t.test/.env"}}},
            "DetectorName": "PrivateKey", "Verified": True, "Raw": "x"})),
        (WpscanTool(), json.dumps({"plugins": {"p": {}}})),
    ]

    @pytest.mark.parametrize("tool,output", CASES, ids=lambda v: getattr(v, "name", ""))
    def test_endpoints_are_addressable(self, tool, output):
        results = tool.parse_output(output, TARGET)
        assert results.endpoints, f"{tool.name} produced nothing to check"
        for endpoint in results.endpoints:
            assert endpoint.url.startswith("http"), \
                f"{tool.name} recorded a hostless endpoint: {endpoint.url!r}"
            assert endpoint.host and endpoint.host != "unknown", \
                f"{tool.name} recorded an unattributed endpoint: {endpoint.host!r}"


class TestFfufNoise:
    """ffuf records everything the server answered, including its catch-all.

    Two distinct problems showed up in the Juice Shop run: the bundled
    wordlist's licence line was fuzzed as a path and persisted as an endpoint,
    and the single-page app answered every word with the same 200, so the whole
    wordlist came back as "found".
    """

    def _run(self, lines, domain="juice_shop:3000"):
        from app.tools.ffuf import FfufTool
        return FfufTool().parse_output("\n".join(lines), domain)

    def test_a_wordlist_licence_line_is_not_an_endpoint(self):
        res = self._run([
            '{"url": "http://juice_shop:3000/# Curated subset of SecLists\' '
            'Discovery/Web-Content/common.txt (MIT License)", "status": 200, "length": 9393}',
            '{"url": "http://juice_shop:3000/admin", "status": 401, "length": 12}',
        ])
        assert [e.url for e in res.endpoints] == ["http://juice_shop:3000/admin"]

    def test_an_identical_catch_all_response_is_suppressed(self):
        """A 200 of the same length for every word is the app, not a finding."""
        res = self._run([
            json.dumps({"url": f"http://juice_shop:3000/{w}", "status": 200, "length": 9393})
            for w in ("admin", "api", "login", "config", "dashboard")
        ])
        assert res.endpoints == []
        assert res.notes, "suppressing every result must be reported, not silent"

    def test_a_gated_endpoint_survives_a_uniform_run(self):
        """A lone 401 among identical 200s is real signal, not noise."""
        res = self._run([
            json.dumps({"url": f"http://juice_shop:3000/{w}", "status": 200, "length": 9393})
            for w in ("admin", "api", "login", "config")
        ] + [
            json.dumps({"url": "http://juice_shop:3000/.env", "status": 401, "length": 40}),
        ])
        assert [e.url for e in res.endpoints] == ["http://juice_shop:3000/.env"]

    def test_a_varied_run_is_kept_in_full(self):
        res = self._run([
            json.dumps({"url": "http://juice_shop:3000/admin", "status": 401, "length": 12}),
            json.dumps({"url": "http://juice_shop:3000/api", "status": 200, "length": 40}),
            json.dumps({"url": "http://juice_shop:3000/graphql", "status": 200, "length": 88}),
        ])
        assert len(res.endpoints) == 3
        assert res.notes == []

    def test_a_404_is_not_a_hit(self):
        res = self._run([
            json.dumps({"url": "http://juice_shop:3000/ghost", "status": 404, "length": 9}),
        ])
        assert res.endpoints == []

    def test_the_command_asks_ffuf_to_skip_the_baseline(self):
        """The filter has to be requested, not only applied after the fact."""
        from app.tools.ffuf import FfufTool
        assert "-fs" in FfufTool().get_command("t.test")
