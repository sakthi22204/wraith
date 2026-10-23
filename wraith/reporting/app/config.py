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
    GRAPH_DB_URL: str = "http://graph_api:8001/api/v1"
    ACTIVE_EXPLOIT_RUNNER_URL: str = "http://active_exploit_runner:8004/api/v1"
    ASSESSMENT_URL: str = "http://assessment_service:8007"
    OUTPUT_DIR: str = "/tmp/reports"
    # auto derives the profile from the investigation's engagement_mode.
    REPORT_PROFILE: str = "auto"
    # No working default. Report generation reads the graph and drives the
    # runner; a published token is not a credential.
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
    profile = (getattr(settings, "REPORT_PROFILE", "") or "auto").strip().lower()
    if profile not in {"auto", "bugcrowd", "hackerone", "redteam"}:
        problems.append(
            f"REPORT_PROFILE is {profile!r}; expected auto, bugcrowd, "
            f"hackerone or redteam"
        )
    if problems:
        raise RuntimeError(
            "Refusing to start reporting with insecure settings: "
            + "; ".join(problems)
        )


settings = Settings()