"""The vendored copy of the runner's grant module must not drift.

`tests/_runner/` exists so the sandbox suite can mint grants with the *runner's*
encoder rather than a hand-written approximation. That only works if the copy is
the real module: a stale copy signs grants the running sandbox rejects, or worse,
accepts grants the running runner would refuse.

This compares them textually, ignoring the one import line that has to differ
(the copy lives under `tests._runner`, so the relative import cannot resolve).
Byte comparison catches drift that a behavioural test would not -- a changed
default TTL, a renamed payload field, a different nonce length -- none of which
break the one fixed vector, because that vector pins only what it exercises.
"""

import pathlib

import pytest

TESTS_DIR = pathlib.Path(__file__).resolve().parent
REPO = TESTS_DIR.parents[1]

PAIRS = [
    ("grant.py", REPO / "active_exploit_runner" / "app" / "roe" / "grant.py"),
    ("authority.py", REPO / "active_exploit_runner" / "app" / "roe" / "authority.py"),
]


def _normalized(text: str) -> list:
    """Drop blank lines and comments; the import rewrite is handled separately."""
    out = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        out.append(stripped)
    return out


@pytest.mark.parametrize("name,source", PAIRS, ids=[p[0] for p in PAIRS])
def test_the_vendored_copy_matches_the_runner(name, source):
    vendored = TESTS_DIR / "_runner" / name

    if not source.exists():
        pytest.skip(f"{source} is not present in this checkout")

    a, b = _normalized(vendored.read_text()), _normalized(source.read_text())

    # The import of the sibling module is the single permitted difference.
    b = [
        ln for ln in b
        if ln not in ("from .authority import normalize_port_claim",
                      "from tests._runner.authority import normalize_port_claim")
    ]

    if a != b:
        import difflib
        diff = "\n".join(difflib.unified_diff(b, a, "runner", "vendored", lineterm=""))
        pytest.fail(
            f"tests/_runner/{name} has drifted from {source.name}. The sandbox "
            f"suite mints grants with this copy, so a stale one tests an encoder "
            f"that no longer exists.\n{diff}"
        )


def test_the_stale_copy_is_not_left_behind():
    """Guards against a rename that leaves the old file imported."""
    assert not (TESTS_DIR / "_runner" / "grant_old.py").exists()