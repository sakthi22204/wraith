"""Make the sandbox suite runnable from the host without pretending it ran.

These tests import the MCP SDK, which lives in the container image rather than
on the host. Collected from a host, that produced ten import errors and pytest
bailed out of the whole run -- so a green-looking absence of failures was in
fact the absence of any test having run at all.

Skipping the directory says the opposite, and says it out loud. It is the same
reasoning as the gate secret and the live database: an error that means "wrong
environment" must not be shaped like an error that means "broken code".
"""

import sys

try:  # pragma: no cover - environment probe, not behaviour
    import mcp  # noqa: F401
    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

if not _MCP_AVAILABLE:
    # Relative to this conftest's own directory, so "*" is everything in
    # tests/. A host run collects nothing and exits 5 ("no tests collected")
    # rather than 0 ("everything passed"). The distinction is the whole point:
    # a zero here would be a claim of success that no test was in a position
    # to make.
    collect_ignore_glob = ["*"]
    print(
        "\n  kali_sandbox: MCP SDK is not installed on this host, so its "
        "tests were not collected.\n"
        "  This suite is container-only. Run it with:\n"
        "      scripts/run_tests.sh sandbox\n"
        "  (exiting 5 here means nothing ran, not that everything passed)\n",
        file=sys.stderr,
    )
