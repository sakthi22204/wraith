from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DOCKER_SOCKET: str = "unix:///var/run/docker.sock"
    LOG_LEVEL: str = "INFO"
    RECON_BROKER_TOKEN: str = "dev-recon-token"
    EXPLOIT_RUNNER_BROKER_TOKEN: str = "dev-exploit-token"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
