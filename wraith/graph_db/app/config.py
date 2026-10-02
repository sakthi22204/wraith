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

# Fields whose whole purpose is to authorize something dangerous or to open a
# database. ADMIN_API_TOKEN guards every write that manufactures trust in the
# graph (findings, reviews, corroboration, CVE links); NEO4J_PASSWORD is a
# database credential whose ports are published on the host.
SECRET_FIELDS = ("ADMIN_API_TOKEN", "NEO4J_PASSWORD")


class Settings(BaseSettings):
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    # No working default. This used to be "password", which is published in
    # docker-compose.yml and in this file, so the graph database was readable by
    # anyone who had seen the repo. Unset is caught by validate_startup_secrets.
    NEO4J_PASSWORD: str = ""
    NEO4J_DATABASE: str = "neo4j"

    POOL_MAX_SIZE: int = 100
    CONNECTION_TIMEOUT: float = 30.0
    # No working default, for the same reason: this is the key behind every
    # trust-manufacturing write route in this service.
    ADMIN_API_TOKEN: str = ""

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


def validate_startup_secrets(settings) -> None:
    """Refuse to start on a blank or well-known secret. Raises RuntimeError.

    Raising is the only safe failure mode here: a graph service that starts
    without these is still reachable, and its unauthenticated-looking write
    routes become real only once a caller supplies the key that gates them.
    """
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
            "Refusing to start graph_db with insecure secrets: "
            + "; ".join(problems)
        )


settings = Settings()