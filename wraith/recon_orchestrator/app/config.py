from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that must never be accepted as a live secret, because they are already
# published in docker-compose.yml and in this repository. A service that starts
# on one of these is running with its primary control disabled.
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

# RECON_BROKER_TOKEN authorizes container creation on the host Docker socket;
# ADMIN_API_TOKEN gates this service's own mutating routes.
SECRET_FIELDS = ("RECON_BROKER_TOKEN", "ADMIN_API_TOKEN")


class Settings(BaseSettings):
    GRAPH_DB_URL: str = "http://localhost:8001/api/v1"
    DOCKER_BROKER_URL: str = "http://localhost:8005/api/v1"
    # No working defaults: both of these authorize something dangerous, and a
    # value baked into the image is a published key rather than a credential.
    # Unset is caught by validate_startup_secrets at startup.
    RECON_BROKER_TOKEN: str = ""
    ADMIN_API_TOKEN: str = ""
    RECON_DOCKER_NETWORK: str = "wraith_wraith_internal"
    TOOL_TIMEOUT: int = 300

    # East-West MITM interception (post-auth beautification layer).
    # When RECON_PROXY_URL is set, supported tools (httpx/katana) route their
    # HTTP(S) traffic through an intercepting mitmproxy and trust its CA, so
    # the orchestrator can persist decrypted request/response evidence.
    # Leave empty (default) to run all tools without a proxy — byte-identical behavior.
    RECON_PROXY_URL: str = ""
    RECON_PROXY_CA_VOLUME: str = "mitmproxy_ca"
    RECON_USER_AGENT: str = ""
    RECON_REQUEST_RATE_LIMIT: int = 10

    # The active runner's ROE rules are the enforcement copy of scope. Recon
    # reconciles its selection scope against them before every scan so the two
    # records cannot drift apart silently.
    RUNNER_URL: str = "http://active_exploit_runner:8004/api/v1"
    RUNNER_ADMIN_TOKEN: str = ""
    RECON_PROXY_CA_PATH: str = "/home/mitmproxy/.mitmproxy"  # mitmproxy image HOME
    RECON_PROXY_CA_CERT_FILE: str = "mitmproxy-ca-cert.pem"

    # Resource limits for tool containers
    MEM_LIMIT: str = "512m"
    CPU_QUOTA: int = 50000  # 0.5 CPU (assuming 100000 default period)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


def validate_startup_secrets(settings) -> None:
    """Refuse to start on a blank or well-known secret. Raises RuntimeError."""
    problems = []
    for field in SECRET_FIELDS:
        value = (getattr(settings, field, "") or "").strip()
        if not value:
            problems.append(f"{field} is empty")
        elif value in KNOWN_INSECURE_SECRETS:
            problems.append(
                f"{field} is set to a value published in this repository "
                f"({value!r}); generate a real secret and inject it"
            )
    if problems:
        raise RuntimeError(
            "Refusing to start recon_orchestrator with insecure secrets: "
            + "; ".join(problems)
        )


settings = Settings()