"""Route extraction from frontend JavaScript.

A single-page app serves one HTML shell and its assets, so ordinary crawling
finds the shell and nothing else: every API route it calls lives as a string
literal inside a bundle. These tests pin the extraction itself, hermetically --
no network, no Juice Shop, no container.
"""
from urllib.parse import urlparse

from app.tools.js_routes import routes_in_js


def paths(found):
    return set(found)


def test_extracts_plain_quoted_routes():
    found = routes_in_js("fetch('/rest/products/search')")

    assert "/rest/products/search" in paths(found)


def test_keeps_hyphens_in_route_segments():
    """A regex that stops at the hyphen turns /change-password into
    /change-password-suffixed-with-garbage, or worse, /change."""
    found = routes_in_js("http.post('/rest/user/change-password')")

    assert "/rest/user/change-password" in paths(found)


def test_preserves_query_parameters():
    found = routes_in_js("fetch('/rest/products/search?q=')")

    assert "/rest/products/search?q=" in paths(found)


def test_reassembles_concatenated_literals():
    found = routes_in_js("fetch('/rest/products/' + id)")

    # The trailing slash is dropped: "/rest/products/" addresses the collection,
    # so probing it with the slash would 404 against the real route.
    assert paths(found) == {"/rest/products"}


def test_reads_template_literal_interpolation_as_a_wildcard():
    found = routes_in_js("fetch(`/rest/user/${id}`)")

    # The interpolated id is dropped, leaving the collection route, which is a
    # real, probeable endpoint.
    assert paths(found) == {"/rest/user"}


def test_captures_the_http_verb_near_the_call():
    found = routes_in_js("this.http.post('/rest/user/login', {})")

    assert found["/rest/user/login"] == {"POST"}


def test_captures_put_and_delete_too():
    found = routes_in_js(
        "this.http.put('/rest/basket/6');"
        "this.http.delete('/rest/basket/6');"
        "this.http.get('/rest/basket');"
    )

    assert found["/rest/basket/6"] == {"PUT", "DELETE"}


def test_same_route_seen_with_two_methods_yields_both_endpoints():
    """The runner keys on URL+method, so a GET and a POST to one path are two
    probes, not one."""
    found = routes_in_js(
        "this.http.get('/rest/basket');"
        "this.http.post('/rest/basket', {});"
    )

    assert found["/rest/basket"] == {"GET", "POST"}


def test_ignores_static_asset_paths():
    body = '"/assets/icons/logo.png" "/assets/js/app.min.js" "/rest/products"'
    found = routes_in_js(body)

    assert not any("logo.png" in p for p in found)
    assert "/rest/products" in found


def test_ignores_paths_outside_api_prefixes():
    body = '"/about" "/contact" "/legal/imprint" "/rest/user/login"'
    found = routes_in_js(body)

    assert paths(found) == {"/rest/user/login"}


def test_extracts_php_ajax_entrypoints():
    """Classic PHP front controllers keep routes in the query string, not in
    the path: a bundle calls "/ajax.php?cat=count". The path-prefix filter must
    not drop these, or a whole application class yields zero recovered routes."""
    found = routes_in_js(
        "$.ajax({url: '/ajax.php?cat=count&t=' + Date.now()});"
        "fetch('/ajax.php?action=search');"
    )

    assert "/ajax.php?cat=count&t=" in paths(found)
    assert "/ajax.php?action=search" in paths(found)


def test_ignores_minified_debris_that_is_not_a_route():
    """Minified JS is dense with brace-and-digit fragments. Without the API
    prefix requirement these flood the endpoint list with junk."""
    body = 'a[n]={0:"x",1:"y"};b[0]="z";var q="ivory",Q=3;'
    found = routes_in_js(body)

    assert paths(found) == set()


def test_keeps_api_prefixed_short_paths():
    found = routes_in_js('"/api/Users" "/api/Challenges" "/api/Feedbacks"')

    assert paths(found) == {"/api/Users", "/api/Challenges", "/api/Feedbacks"}


def test_anchors_routes_to_the_target_not_to_the_bundle():
    """Regression: reading a route out of /main.js must not produce
    /main.js/rest/... -- the route is served by the target, not the bundle."""
    found = routes_in_js("fetch('/rest/products/search')")

    assert all(".js/" not in u for u in found)


def test_strips_fragment():
    found = routes_in_js("fetch('/rest/products#top')")

    assert all("#" not in p for p in found)


def test_survives_a_bundle_with_no_api_routes():
    assert paths(routes_in_js("var a=1;function b(){return null}")) == set()


def test_survives_binary_looking_input_without_raising():
    assert paths(routes_in_js("\x00\x01\x02\xff garbage")) == set()


def test_absolute_url_route_is_not_turned_into_a_probe():
    """A bundle may name any absolute URL. None is adopted as a target here, so
    a page cannot steer recon at a third-party host; only root-relative paths
    are recovered."""
    found = routes_in_js(
        "fetch('https://evil.example/rest/products')"
        "fetch('http://elsewhere.test/rest/admin')"
    )

    assert paths(found) == set()


def test_same_host_absolute_route_is_also_dropped():
    """Known limitation, pinned so it is a decision rather than a surprise: an
    absolute route for the target itself is not recovered."""
    found = routes_in_js("fetch('http://t.test/rest/products')")

    assert paths(found) == set()


def test_deduplicates_repeated_routes():
    found = routes_in_js(
        "fetch('/rest/products');fetch('/rest/products');fetch('/rest/products');"
    )

    assert found["/rest/products"] == {"GET"}


def test_endpoint_carries_host_and_method():
    found = routes_in_js("this.http.post('/rest/user/login', {})")

    assert found["/rest/user/login"] == {"POST"}


def test_respects_route_cap():
    """A hostile or generated bundle must not be able to flood the graph."""
    body = " ".join(f"fetch('/rest/item{i}')" for i in range(500))
    found = routes_in_js(body)

    assert 0 < len(found) <= 300
