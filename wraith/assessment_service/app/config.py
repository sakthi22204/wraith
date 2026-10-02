import os
from pydantic_settings import BaseSettings, SettingsConfigDict

# Values that must never be accepted as a live secret, because they are already
# published in docker-compose.yml and in this repository.
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

SECRET_FIELDS = ("ADMIN_API_TOKEN",)


class Settings(BaseSettings):
    GRAPH_DB_URL: str = os.getenv("GRAPH_DB_URL", "http://graph_api:8001/api/v1")
    # No working default. This service's routes read the whole graph and drive
    # assessment runs; a published token is not a credential.
    ADMIN_API_TOKEN: str = ""

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
            "Refusing to start assessment_service with insecure secrets: "
            + "; ".join(problems)
        )


settings = Settings()