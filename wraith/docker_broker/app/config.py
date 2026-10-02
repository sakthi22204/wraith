from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that must never be accepted as a live secret, because they are already
# published in docker-compose.yml and in this repository. A service that starts
# on one of these is running with its primary control disabled: whoever has read
# the repo holds the key.
#
# Listed centrally so that adding a default to a compose file or a config class
# without adding it here fails the startup test rather than passing review.
KNOWN_INSECURE_SECRETS = frozenset({
    "",
    "dev-recon-token",
    "dev-exploit-token",
    "dev-token-change-me",
    "wraith-dev-gate-secret",
    "password",
    "changeme",
    "change-me",
    "secret",
})

# Fields whose whole purpose is to authorize something dangerous.
SECRET_FIELDS = ("RECON_BROKER_TOKEN", "EXPLOIT_RUNNER_BROKER_TOKEN")


class Settings(BaseSettings):
    DOCKER_SOCKET: str = "unix:///var/run/docker.sock"
    LOG_LEVEL: str = "INFO"
    # No defaults on purpose. These authorize creating containers on the host
    # Docker socket; a value baked into the image is not a credential, it is a
    # published key. Unset is caught by validate_startup_secrets at startup.
    RECON_BROKER_TOKEN: str = ""
    EXPLOIT_RUNNER_BROKER_TOKEN: str = ""
    RECON_DOCKER_NETWORK: str = "wraith_wraith_internal"
    # Cap on how many trailing log lines a single tool run may return. Without
    # a bound, container.logs() defaults to tail="all" and buffers the entire
    # output in memory; high-volume tools (gau/waybackurls emit 100k+ JSON
    # lines) drove this process to ~7GB RSS and the kernel OOM-killed the
    # broker, which then failed every in-flight tool spawn.
    LOG_TAIL_LINES: int = 50000

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


def validate_startup_secrets(settings) -> None:
    """Refuse to start on a blank or well-known secret. Raises RuntimeError.

    Raising here is deliberate: this broker can run arbitrary whitelisted images
    on the host socket, so the only safe failure mode is to not be running.
    """
    problems = []
    for field in SECRET_FIELDS:
        value = getattr(settings, field, "") or ""
        if not value.strip():
            problems.append(f"{field} is empty")
        elif value.strip() in KNOWN_INSECURE_SECRETS:
            problems.append(
                f"{field} is set to a value published in this repository "
                f"({value.strip()!r}); generate a real secret and inject it"
            )
    if problems:
        raise RuntimeError(
            "Refusing to start the Docker broker with insecure secrets: "
            + "; ".join(problems)
        )


settings = Settings()