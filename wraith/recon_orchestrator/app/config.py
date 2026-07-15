from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    GRAPH_DB_URL: str = "http://localhost:8001/api/v1"
    DOCKER_BROKER_URL: str = "http://localhost:8005/api/v1"
    RECON_BROKER_TOKEN: str = "dev-recon-token"
    ADMIN_API_TOKEN: str = "dev-token-change-me"
    TOOL_TIMEOUT: int = 300

    # Resource limits for tool containers
    MEM_LIMIT: str = "512m"
    CPU_QUOTA: int = 50000  # 0.5 CPU (assuming 100000 default period)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
