from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GRAPH_DB_URL: str = "http://graph_api:8001/api/v1"
    ACTIVE_EXPLOIT_RUNNER_URL: str = "http://active_exploit_runner:8004/api/v1"
    OUTPUT_DIR: str = "/tmp/reports"
    ADMIN_API_TOKEN: str = "dev-token-change-me"

    class Config:
        env_file = ".env"

settings = Settings()
