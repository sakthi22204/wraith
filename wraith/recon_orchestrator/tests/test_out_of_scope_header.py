"""The scope-rejection header is built from raw client input.

`out_of_scope` holds whatever the caller posted, so the header must never be a
conduit for injected content -- a partial list is fine, a forged header is not.
"""

from app.orchestrator import OUT_OF_SCOPE_HEADER, out_of_scope_headers


class TestOutOfScopeHeaders:
    def test_bare_hostnames_are_forwarded(self):
        headers = out_of_scope_headers(["evil.com", "foo.test"])
        assert headers == {OUT_OF_SCOPE_HEADER: "evil.com,foo.test"}

    def test_surrounding_whitespace_is_trimmed(self):
        headers = out_of_scope_headers([" evil.com "])
        assert headers[OUT_OF_SCOPE_HEADER] == "evil.com"

    def test_header_is_omitted_when_nothing_survives(self):
        assert out_of_scope_headers([]) == {}
        assert out_of_scope_headers([""]) == {}
        assert out_of_scope_headers(["   "]) == {}

    def test_crlf_injection_is_dropped_not_escaped(self):
        headers = out_of_scope_headers(["evil.com\r\nX-Evil: 1"])
        assert OUT_OF_SCOPE_HEADER not in headers

    def test_ports_paths_urls_and_markup_are_dropped(self):
        for hostile in [
            "evil.com:8080",
            "/etc/passwd",
            "http://internal-host/admin",
            "<script>alert(1)</script>",
            "evil.com evil2.com",
            "evil.com\nfoo.test",
        ]:
            assert out_of_scope_headers([hostile]) == {}, hostile

    def test_a_poisoned_entry_does_not_take_the_good_ones_with_it(self):
        headers = out_of_scope_headers(["evil.com", "evil.com\r\nX-Evil: 1"])
        assert headers[OUT_OF_SCOPE_HEADER] == "evil.com"

    def test_the_list_is_capped(self):
        many = [f"host{i}.test" for i in range(50)]
        value = out_of_scope_headers(many)[OUT_OF_SCOPE_HEADER]
        assert value.count(",") == 9
        assert len(value) < 300

    def test_subdomains_and_apexes_pass_through(self):
        headers = out_of_scope_headers(["api.dev.crypto.com", "crypto.com"])
        assert headers[OUT_OF_SCOPE_HEADER] == "api.dev.crypto.com,crypto.com"
