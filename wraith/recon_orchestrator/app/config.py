from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    GRAPH_DB_URL: str = "http://localhost:8001/api/v1"
    DOCKER_BROKER_URL: str = "http://localhost:8005/api/v1"
    RECON_BROKER_TOKEN: str = "dev-recon-token"
    ADMIN_API_TOKEN: str = "dev-token-change-me"
    RECON_DOCKER_NETWORK: str = "wraith_wraith_internal"
    TOOL_TIMEOUT: int = 300

    # East-West MITM interception (post-auth beautification layer).
    # When RECON_PROXY_URL is set, supported tools (httpx/katana) route their
    # HTTP(S) traffic through an intercepting mitmproxy and trust its CA, so
    # the orchestrator can persist decrypted request/response evidence.
    # Leave empty (default) to run all tools without a proxy — byte-identical behavior.
    RECON_PROXY_URL: str = ""
    RECON_PROXY_CA_VOLUME: str = "mitmproxy_ca"
    RECON_PROXY_CA_PATH: str = "/home/mitmproxy/.mitmproxy"  # mitmproxy image HOME
    RECON_PROXY_CA_CERT_FILE: str = "mitmproxy-ca-cert.pem"

    # Resource limits for tool containers
    MEM_LIMIT: str = "512m"
    CPU_QUOTA: int = 50000  # 0.5 CPU (assuming 100000 default period)

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
