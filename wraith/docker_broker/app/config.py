from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    DOCKER_SOCKET: str = "unix:///var/run/docker.sock"
    LOG_LEVEL: str = "INFO"
    RECON_BROKER_TOKEN: str = "dev-recon-token"
    EXPLOIT_RUNNER_BROKER_TOKEN: str = "dev-exploit-token"
    RECON_DOCKER_NETWORK: str = "wraith_wraith_internal"
    # Cap on how many trailing log lines a single tool run may return. Without
    # a bound, container.logs() defaults to tail="all" and buffers the entire
    # output in memory; high-volume tools (gau/waybackurls emit 100k+ JSON
    # lines) drove this process to ~7GB RSS and the kernel OOM-killed the
    # broker, which then failed every in-flight tool spawn.
    LOG_TAIL_LINES: int = 50000

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

settings = Settings()
