"""A service that holds host-level authority must refuse to start on a default secret.

These tests pin a startup refusal, not a runtime check. The reason is that every
one of these secrets is a *bypass*, not a credential:

* the broker tokens authorize creating containers on the host Docker socket;
* the gate secret signs the grants the sandbox trusts as proof a request was
  scoped, killswitched and rate-limited on the way in;
* the runner's admin token authorizes the killswitch and the evidence write
  paths.

Shipping them with a value already published in docker-compose.yml and in this
repository means the control is decorative: an attacker who has read the repo
has the key. Refusing to start is the only version of "change this" that anyone
actually enforces.
"""
import asyncio
from contextlib import contextmanager

import pytest

from app.config import KNOWN_INSECURE_SECRETS, validate_startup_secrets


def _settings(**overrides):
    base = {
        "RECON_BROKER_TOKEN": "a-real-recon-token",
        "EXPLOIT_RUNNER_BROKER_TOKEN": "a-real-runner-token",
    }
    base.update(overrides)
    return type("S", (), base)()


@contextmanager
def patched_settings(**overrides):
    """Temporarily set fields on the module-level settings singleton."""
    from app import config as config_module

    saved = {k: getattr(config_module.settings, k) for k in overrides}
    for k, v in overrides.items():
        setattr(config_module.settings, k, v)
    try:
        yield
    finally:
        for k, v in saved.items():
            setattr(config_module.settings, k, v)


def test_valid_secrets_pass():
    validate_startup_secrets(_settings())


@pytest.mark.parametrize("field", ["RECON_BROKER_TOKEN", "EXPLOIT_RUNNER_BROKER_TOKEN"])
@pytest.mark.parametrize("value", ["", "   "])
def test_blank_token_refuses_to_start(field, value):
    with pytest.raises(RuntimeError) as exc:
        validate_startup_secrets(_settings(**{field: value}))
    assert field in str(exc.value)


@pytest.mark.parametrize("field", ["RECON_BROKER_TOKEN", "EXPLOIT_RUNNER_BROKER_TOKEN"])
def test_published_default_token_refuses_to_start(field):
    """The compose file used to supply dev-recon-token / dev-exploit-token, and
    config.py shipped the same strings as code defaults."""
    with pytest.raises(RuntimeError) as exc:
        validate_startup_secrets(_settings(**{field: "dev-recon-token"}))
    assert field in str(exc.value)


def test_the_published_defaults_are_actually_known_to_the_validator():
    """Guard against the list drifting: if a default ships again, the validator
    must already name it."""
    for known in ("dev-recon-token", "dev-exploit-token", "wraith-dev-gate-secret",
                  "dev-token-change-me", "password"):
        assert known in KNOWN_INSECURE_SECRETS


def test_refusal_happens_before_anything_is_pulled(monkeypatch):
    """The startup hook pre-pulls ~20 images. It must not do that work, or leave
    a half-provisioned broker, when it is about to refuse anyway."""
    import docker

    from app.main import startup_event

    pulled = []

    class _FakeImages:
        def get(self, image):
            raise docker.errors.ImageNotFound(image)

        def pull(self, image):
            pulled.append(image)

    class _FakeClient:
        images = _FakeImages()

    monkeypatch.setattr(docker, "from_env", lambda *a, **k: _FakeClient())

    with patched_settings(RECON_BROKER_TOKEN=""):
        with pytest.raises(RuntimeError) as exc:
            asyncio.run(startup_event())

    assert "RECON_BROKER_TOKEN" in str(exc.value)
    assert pulled == [], "images were pulled before the secret refusal"


def test_healthy_startup_still_pulls_images(monkeypatch):
    """The guard must not have costed us the pre-pull."""
    import docker

    from app.main import startup_event

    pulled = []

    class _FakeImages:
        def get(self, image):
            raise docker.errors.ImageNotFound(image)

        def pull(self, image):
            pulled.append(image)

    class _FakeClient:
        images = _FakeImages()

    monkeypatch.setattr(docker, "from_env", lambda *a, **k: _FakeClient())

    with patched_settings(
        RECON_BROKER_TOKEN="a-real-recon-token",
        EXPLOIT_RUNNER_BROKER_TOKEN="a-real-runner-token",
    ):
        asyncio.run(startup_event())

    assert pulled, "valid secrets should still pre-pull the tool images"