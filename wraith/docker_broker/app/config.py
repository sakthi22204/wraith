from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DOCKER_SOCKET: str = "unix:///var/run/docker.sock"
    LOG_LEVEL: str = "INFO"

    # Per-service tokens for ownership isolation
    RECON_ORCHESTRATOR_TOKEN: str = "recon-dev-token"
    ACTIVE_EXPLOIT_RUNNER_TOKEN: str = "exploit-dev-token"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
