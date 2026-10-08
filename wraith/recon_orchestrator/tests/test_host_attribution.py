"""An archive URL can contain a whole URL in its path.

gau emits lines like::

    https://tax.crypto.com/%20is%20US%20only.%20I%20used%20https://koinly.io/

Splitting on ``://`` and keeping the last piece attributes that endpoint to
``koinly.io``, so an unrelated third party lands in the graph as a discovered
host of the scoped target. These cases pin the authority parsing that prevents it.
"""
from app.tools.base import host_from_domain


def test_embedded_url_in_path_keeps_real_host():
    url = "https://tax.crypto.com/%20is%20US%20only.%20I%20used%20https://koinly.io/"
    assert host_from_domain(url) == "tax.crypto.com"


def test_plain_url_and_domain():
    assert host_from_domain("https://tax.crypto.com/api/users/me") == "tax.crypto.com"
    assert host_from_domain("tax.crypto.com") == "tax.crypto.com"
    assert host_from_domain("HTTP://Tax.Crypto.COM/x") == "tax.crypto.com"


def test_port_is_stripped():
    assert host_from_domain("https://tax.crypto.com:8443/api") == "tax.crypto.com"


def test_path_only_and_empty():
    assert host_from_domain("") == ""
    assert host_from_domain("   ") == ""


def test_query_string_does_not_leak_into_host():
    assert host_from_domain("https://tax.crypto.com/r?next=https://evil.io/") == "tax.crypto.com"