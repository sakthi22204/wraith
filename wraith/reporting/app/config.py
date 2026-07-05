from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GRAPH_DB_URL: str = "http://graph_db:8000"
    ACTIVE_EXPLOIT_RUNNER_URL: str = "http://active_exploit_runner:8004"
    OUTPUT_DIR: str = "/tmp/reports"

    class Config:
        env_file = ".env"

settings = Settings()
