import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    GRAPH_DB_URL: str = os.getenv("GRAPH_DB_URL", "http://graph_api:8001/api/v1")
    ADMIN_API_TOKEN: str = os.getenv("ADMIN_API_TOKEN", "dev-token-change-me")

settings = Settings()
