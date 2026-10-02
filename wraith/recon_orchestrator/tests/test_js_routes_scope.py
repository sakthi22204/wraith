"""Bundle fetching stays inside the target's own origin.

The script list is parsed out of attacker-visible HTML: a page can name any URL
it likes in a ``<script src>``. js_routes fetches those URLs in-process, from
inside the trusted network, without a broker container. If it followed an
arbitrary name, recon would become a request-forgery primitive and the request
would originate from the wrong place. These tests pin that boundary, plus the
HTML-level extraction that feeds it.
"""
import httpx
import pytest

from app.tools.js_routes import JsRoutesTool


TARGET = "juice_shop"
ORIGIN = f"http://{TARGET}:3000"


def tool():
    return JsRoutesTool()


def test_allows_the_targets_own_origin():
    assert tool()._is_same_origin(f"{ORIGIN}/main.js", TARGET) is True


def test_allows_any_path_on_the_target():
    assert tool()._is_same_origin(f"{ORIGIN}/assets/js/vendor.js", TARGET) is True


def test_rejects_a_different_host():
    assert tool()._is_same_origin("http://evil.example/main.js", TARGET) is False


def test_rejects_a_host_that_merely_contains_the_target():
    """A suffix check would accept juice_shop.evil.example, which is an
    attacker-controlled host that has the target's name in it."""
    assert tool()._is_same_origin("http://juice_shop.evil.example/main.js", TARGET) is False


def test_rejects_a_host_that_is_a_prefix_of_the_target():
    assert tool()._is_same_origin("http://juice_shop2:3000/main.js", TARGET) is False


def test_rejects_a_userinfo_trick():
    """The hostname parses as juice_shop while the request actually goes to
    evil.example -- the classic way a naive string check is defeated."""
    assert tool()._is_same_origin(f"http://{TARGET}@evil.example/main.js", TARGET) is False


def test_rejects_a_non_http_scheme():
    assert tool()._is_same_origin("file:///etc/passwd", TARGET) is False
    assert tool()._is_same_origin("ftp://juice_shop/main.js", TARGET) is False


def test_rejects_an_empty_host():
    assert tool()._is_same_origin(f"{ORIGIN}/main.js", "") is False


def test_host_comparison_ignores_case():
    assert tool()._is_same_origin(f"http://JUICE_SHOP:3000/main.js", "juice_shop") is True


def test_collects_script_srcs_from_html():
    html = '<script src="/main.js"></script><script src="/assets/vendor.js?v=2"></script>'
    urls = tool()._bundle_urls(ORIGIN, html, TARGET)

    assert f"{ORIGIN}/main.js" in urls
    assert f"{ORIGIN}/assets/vendor.js?v=2" in urls


def test_ignores_inline_scripts_and_non_js_sources():
    html = '<script>var x = 1;</script><script src="/app.css"></script>'
    assert tool()._bundle_urls(ORIGIN, html, TARGET) == []


def test_drops_off_origin_script_srcs_from_the_bundle_list():
    """The important one: an off-origin src must not reach the fetch list."""
    html = (
        '<script src="/main.js"></script>'
        '<script src="https://cdn.evil.example/tracker.js"></script>'
    )
    urls = tool()._bundle_urls(ORIGIN, html, TARGET)

    assert urls == [f"{ORIGIN}/main.js"]


def test_resolves_relative_script_srcs_against_the_target():
    html = '<script src="main.js"></script><script src="./a/b.js"></script>'
    urls = tool()._bundle_urls(ORIGIN, html, TARGET)

    assert f"{ORIGIN}/main.js" in urls
    assert f"{ORIGIN}/a/b.js" in urls


def test_deduplicates_repeated_script_srcs():
    html = '<script src="/main.js"></script><script src="/main.js"></script>'
    assert tool()._bundle_urls(ORIGIN, html, TARGET) == [f"{ORIGIN}/main.js"]


def test_accepts_single_quoted_and_uppercase_script_tags():
    html = "<SCRIPT SRC='/main.js'></SCRIPT>"
    assert tool()._bundle_urls(ORIGIN, html, TARGET) == [f"{ORIGIN}/main.js"]


def test_bundles_tolerate_malformed_html():
    html = '<script src="/main.js"'  # never closed
    assert tool()._bundle_urls(ORIGIN, html, TARGET) == [f"{ORIGIN}/main.js"]


def test_get_refuses_an_off_origin_url_without_touching_the_network():
    """A refusal must happen before any request is issued."""

    class ExplodingClient:
        def stream(self, *a, **k):  # pragma: no cover - must not run
            raise AssertionError("network touched for an out-of-scope URL")

    result = asyncio_run(tool()._get(ExplodingClient(), "http://evil.example/x.js", 1000, TARGET))
    assert result is None


def test_get_follows_a_same_origin_redirect():
    """A page that 302s to another path on itself is normal and must still be read."""

    async def go():
        def handler(request):
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "/index.html"})
            return httpx.Response(200, text="fetch('/rest/products')")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await tool()._get(client, f"{ORIGIN}/", 10_000, TARGET)

    assert "/rest/products" in asyncio_run(go())


def test_get_refuses_a_redirect_that_leaves_the_target():
    """The scope check must apply to every hop, not just the first URL. An
    open redirect on the target would otherwise carry the fetch off-origin."""

    async def go():
        def handler(request):
            if request.url.path == "/":
                return httpx.Response(302, headers={"location": "http://evil.example/x.js"})
            raise AssertionError(f"followed off-origin to {request.url}")

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await tool()._get(client, f"{ORIGIN}/", 10_000, TARGET)

    assert asyncio_run(go()) is None


def test_get_refuses_a_redirect_loop_instead_of_hanging():
    async def go():
        def handler(request):
            return httpx.Response(302, headers={"location": "/loop"})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            return await tool()._get(client, f"{ORIGIN}/loop", 10_000, TARGET)

    assert asyncio_run(go()) is None


def test_get_returns_none_when_the_target_refuses_the_bundle():
    async def go():
        transport = httpx.MockTransport(lambda request: httpx.Response(404))
        async with httpx.AsyncClient(transport=transport) as client:
            return await tool()._get(client, f"{ORIGIN}/missing.js", 1000, TARGET)

    assert asyncio_run(go()) is None


def test_get_truncates_an_oversized_bundle_instead_of_buffering_it_all():
    async def go():
        body = "x" * 50_000
        transport = httpx.MockTransport(lambda request: httpx.Response(200, text=body))
        async with httpx.AsyncClient(transport=transport) as client:
            return await tool()._get(client, f"{ORIGIN}/big.js", limit=1000, host=TARGET)

    out = asyncio_run(go())
    assert out is not None
    assert len(out) == 1000


def test_run_in_process_reports_a_dead_target_instead_of_raising():
    """A parsing aid must never fail a recon run."""

    async def go():
        transport = httpx.MockTransport(lambda request: httpx.Response(503))
        async with httpx.AsyncClient(transport=transport) as client:
            return await JsRoutesTool().run_in_process(TARGET, client=client)

    results = asyncio_run(go())
    assert list(results.endpoints) == []
    assert any("bundle" in n for n in results.notes)


def asyncio_run(coro):
    import asyncio
    return asyncio.run(coro)
