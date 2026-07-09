from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DOCKER_SOCKET: str = "unix:///var/run/docker.sock"
    LOG_LEVEL: str = "INFO"
    DOCKER_BROKER_TOKEN: str = "dev-token-change-me"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
