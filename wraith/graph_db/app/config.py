from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    NEO4J_URI: str = "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "password"
    NEO4J_DATABASE: str = "neo4j"

    POOL_MAX_SIZE: int = 100
    CONNECTION_TIMEOUT: float = 30.0
    ADMIN_API_TOKEN: str = "dev-token-change-me"

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
