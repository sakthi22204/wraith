import re
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlsplit

import httpx

from .base import ReconTool, target_url, host_from_domain
from ..schemas import ToolResults, EndpointResult
from ..config import settings


# Only paths under one of these prefixes are treated as routes. Without the
# prefix requirement, a generic path regex over a minified bundle returns the
# code's own debris: on Juice Shop's main.js that was 247 junk paths ("/.]",
# "/100;return", "/0x8343d2eb2B13A2495...") against 49 real routes. The prefix is
# what separates a route table from tokenised source. A .php front controller is
# included because classic applications put the route in the query
# ("/ajax.php?cat=count"), which a path-only prefix list would drop entirely.
_API_PREFIX = r"(?:rest|api|graphql|gql|v\d+|[A-Za-z0-9_-]+\.php)"

# The route literal, not just a path. A framework client builds its URL as
# `this.http.get(`${this.host}/rest/products/search?q=${term}`)`, and in that
# -- the dominant shape -- the path does NOT follow the opening quote: an
# interpolation does. Requiring the quote to sit against the path matches only
# the minority form where the literal is the path alone, which on Juice Shop's
# main.js is 41 of 49 routes and, critically, misses /rest/products/search --
# the one an injection test needs. So an optional interpolation prefix is
# consumed here, and _INTERP_RE strips any that survive inside the query.
#
# The path may carry the query string that names the parameter a payload would
# have to be driven into; without it there is no parameter to test.
#
# The character class puts '-' last so it is a literal. The equivalent-looking
# `[a-zA-Z0-9.-_/]` is not the same thing -- Python reads `.-_` as a character
# *range* (0x2E-0x5F), which excludes '-' (0x2D) and silently truncates every
# hyphenated route: "/rest/user/change-password" matches as "/rest/user", i.e.
# the hyphenated route and its parent collapse into one endpoint.
_ROUTE_RE = re.compile(
    r"[`'\"]"
    r"(?:\$\{[^}]*\}\s*)?"
    r"("
    rf"/{_API_PREFIX}"
    r"(?:/[A-Za-z0-9._~%-]+)*"
    r"(?:\?[^`'\"]*)?"
    r")",
    re.I,
)

# `${this.id}` and friends inside a captured query: the variable is the value
# the app would substitute, not part of the route. Removing it leaves "q=",
# which still names the parameter.
_INTERP_RE = re.compile(r"\$\{[^}]*\}")

# The verb, taken from the client call that owns the literal. The look-back is
# bounded and takes the *last* verb before the literal, because minified code
# packs many calls into one line and the nearest enclosing call is the one that
# reaches this URL.
_VERB_RE = re.compile(r"\.\s*(get|post|put|patch|delete)\s*\(", re.I)
_VERB_LOOKBEHIND = 240
_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}

# A route is short and its segments are words. These bounds are not
# arbitrary: they reject the shapes that minified code produces by accident
# while leaving real REST paths alone.
_MAX_PATH_LEN = 200
_MAX_SEGMENTS = 8
_HASHLIKE_RE = re.compile(r"^[0-9a-fA-F]{16,}$")

_SCRIPT_SRC_RE = re.compile(
    r"""<script[^>]+?src\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']""", re.I
)

# Bounds on the in-process fetches. This tool runs inside the recon service
# rather than in a broker container, so its network reach is its own
# responsibility: it must not be able to walk the internet or pull an
# unbounded amount of data into the service.
_MAX_BUNDLES = 10
_MAX_BUNDLE_BYTES = 5_000_000
_MAX_HTML_BYTES = 1_000_000
# Routes kept from a single bundle. A real application bundle carries tens of
# routes; a generated or hostile one can carry thousands of string literals, and
# every endpoint recovered here becomes a probe the rest of the pipeline plans,
# validates and stores. Truncation is announced in the tool notes rather than
# done silently, so a partial route table is never read as a complete one.
_MAX_ROUTES_PER_BUNDLE = 300

# Redirects followed by hand (see JsRoutesTool._get). A page that bounces
# around is normal; one that bounces indefinitely is not.
_MAX_REDIRECTS = 3
_REDIRECT_CODES = (301, 302, 303, 307, 308)


class JsRoutesTool(ReconTool):
    """Recover API routes from a target's own JavaScript bundles.

    A single-page application keeps its route table in its JavaScript, not in
    its HTML. Nothing in the served HTML points at /rest/products/search, so a
    crawler following links and a wordlist sweeping paths both come back with
    the shell and its static assets and never with the API -- on Juice Shop,
    49 routes were present in main.js and 0 were discovered.

    That is not a gap in the wordlists or the crawler. It is a gap in what the
    pipeline reads: katana already recorded main.js as an endpoint, and nothing
    ever looked inside it. This tool does, and reports each route with the HTTP
    verb the bundle actually uses, because a POST-only rule (injection canary,
    race, mass assignment) cannot fire against endpoints recorded as GET.
    """

    timeout = 180

    def __init__(self):
        # image=None selects the in-process path in ReconTool.run.
        super().__init__(name="js_routes")

    # -- fetching ---------------------------------------------------------

    async def run_in_process(self, domain: str, client: Optional[httpx.AsyncClient] = None) -> ToolResults:
        results = ToolResults()
        base = target_url(domain).rstrip("/")
        target_host = host_from_domain(domain)
        try:
            async with httpx.AsyncClient(
                timeout=settings.TOOL_TIMEOUT,
                follow_redirects=False,
                verify=False,
            ) as owned:
                http = client or owned
                html = await self._get(http, base, _MAX_HTML_BYTES, target_host)
                if html is None:
                    results.notes.append(
                        f"js_routes: could not read {base}; no bundles parsed"
                    )
                    return results

                bundles = self._bundle_urls(base, html, target_host)
                if not bundles:
                    results.notes.append(
                        f"js_routes: {base} served no external .js bundle; "
                        "nothing to extract routes from"
                    )
                    return results

                parsed = 0
                skipped: List[str] = []
                for url in bundles[:_MAX_BUNDLES]:
                    body = await self._get(http, url, _MAX_BUNDLE_BYTES, target_host)
                    if body is None:
                        skipped.append(url)
                        continue
                    parsed += 1
                    # Anchor to the site, not to the bundle the route was read
                    # out of: the route is served by the target, so its URL is
                    # target + path. Using the bundle here yields
                    # ".../main.js/rest/products/search".
                    self._absorb(body, base, target_host, results)

                if len(bundles) > _MAX_BUNDLES:
                    results.notes.append(
                        f"js_routes: {len(bundles)} bundles referenced, parsed the "
                        f"first {_MAX_BUNDLES}"
                    )
                if skipped:
                    results.notes.append(
                        f"js_routes: {len(skipped)} bundle(s) unread: "
                        + ", ".join(skipped[:3])
                    )
                if parsed == 0:
                    results.notes.append("js_routes: no bundle could be read")
        except Exception as exc:  # a parsing aid must never fail a recon run
            results.notes.append(f"js_routes: aborted after {type(exc).__name__}: {exc}")

        return results

    async def _get(
        self, client: httpx.AsyncClient, url: str, limit: int, host: str
    ) -> Optional[str]:
        """GET one in-scope URL, or None. Never leaves the target's origin.

        Redirects are followed by hand rather than by httpx, because the
        client-level ``follow_redirects`` cannot be scope-checked: it would
        honour a ``Location`` pointing anywhere, and the scope test below only
        ever sees the first URL. Each hop is therefore re-checked here, so a
        redirect cannot carry the fetch off the target.
        """
        for _ in range(_MAX_REDIRECTS + 1):
            if not self._is_same_origin(url, host):
                return None
            try:
                async with client.stream("GET", url) as response:
                    if response.status_code in _REDIRECT_CODES:
                        location = response.headers.get("location", "")
                        if not location:
                            return None
                        url = urljoin(url, location)
                        continue
                    if response.status_code != 200:
                        return None
                    chunks: List[bytes] = []
                    total = 0
                    async for chunk in response.aiter_bytes():
                        total += len(chunk)
                        if total > limit:
                            chunks.append(chunk[: limit - (total - len(chunk))])
                            break
                        chunks.append(chunk)
                    return b"".join(chunks).decode("utf-8", "replace")
            except Exception:
                return None
        return None

    def _bundle_urls(self, base: str, html: str, host: str) -> List[str]:
        seen: Set[str] = set()
        out: List[str] = []
        for src in _SCRIPT_SRC_RE.findall(html):
            url = urljoin(base + "/", src.strip())
            if self._is_same_origin(url, host) and url not in seen:
                seen.add(url)
                out.append(url)
        return out

    # -- scope ------------------------------------------------------------

    def _is_same_origin(self, url: str, host: str) -> bool:
        """Only the target's own origin is fetched.

        The bundle list is parsed out of attacker-visible HTML, so a page can
        name any URL it likes. Following one would turn recon into a request
        forgery primitive against whatever host the page names, and the request
        would originate from inside the trusted network rather than from a
        broker container. Every fetch is therefore pinned to the target host.
        """
        if not host:
            return False
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https"):
            return False
        return (parts.hostname or "").lower() == host.lower()

    # -- parsing ----------------------------------------------------------

    def _absorb(self, body: str, base_url: str, host: str, results: ToolResults) -> None:
        seen: Set[Tuple[str, str]] = set()
        for match in _ROUTE_RE.finditer(body):
            raw = match.group(1)
            path = self._normalise(raw)
            if not path:
                continue
            verb = self._verb_for(body, match.start())
            key = (path, verb)
            if key in seen:
                continue
            if len(seen) >= _MAX_ROUTES_PER_BUNDLE:
                results.notes.append(
                    f"js_routes: route table truncated at {_MAX_ROUTES_PER_BUNDLE} "
                    "entries; the bundle carries more API-shaped literals than "
                    "this bound allows"
                )
                break
            seen.add(key)
            results.endpoints.append(EndpointResult(
                host=host,
                url=f"{target_url(base_url).rstrip('/')}{path}",
                method=verb,
                source_tool=self.name,
            ))

    @staticmethod
    def _normalise(raw: str) -> str:
        path = _INTERP_RE.sub("", raw).split("#", 1)[0]
        if len(path) > _MAX_PATH_LEN:
            return ""
        segments = [s for s in path.split("/") if s]
        if not segments or len(segments) > _MAX_SEGMENTS:
            return ""
        for segment in segments:
            if _HASHLIKE_RE.match(segment):
                # A 16+ hex-digit segment is a build hash or an id inlined by the
                # bundler, not a route.
                return ""
        # "/rest/basket/" addresses "/rest/basket/{id}"; the trailing slash is
        # the collection, and probing the slash would 404 against the real one.
        return "/" + "/".join(segments)

    @staticmethod
    def _verb_for(body: str, route_start: int) -> str:
        window = body[max(0, route_start - _VERB_LOOKBEHIND):route_start]
        best: Optional[str] = None
        for verb_match in _VERB_RE.finditer(window):
            best = verb_match.group(1).upper()
        return best if best in _METHODS else "GET"

    # -- test surface -----------------------------------------------------

    def parse_routes(self, body: str, base_url: str, host: str) -> List[EndpointResult]:
        """Pure parse of one bundle. Split out so it can be tested without a fetch."""
        results = ToolResults()
        self._absorb(body, base_url, host, results)
        return list(results.endpoints)


def routes_in_js(body: str) -> Dict[str, Set[str]]:
    """Map of route -> verbs found in a JavaScript bundle. Used by the tests.

    Keyed on path *and* query: the query is what names the parameter a payload
    test would drive, so dropping it here would hide exactly the routes an
    injection candidate is built from.
    """
    found: Dict[str, Set[str]] = {}
    tool = JsRoutesTool()
    for endpoint in tool.parse_routes(body, "http://t.test", "t.test"):
        parts = urlsplit(endpoint.url)
        key = parts.path + (f"?{parts.query}" if parts.query else "")
        found.setdefault(key, set()).add(endpoint.method)
    return found
