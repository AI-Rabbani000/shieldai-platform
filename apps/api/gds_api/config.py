from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# parents[0]=gds_api, [1]=src, [2]=api, [3]=apps, [4]=repo root. Getting this index wrong
# means .env is silently never read and Settings() falls back to class defaults with no
# error — verify with `python -c "from gds_api.config import _ROOT_ENV; print(_ROOT_ENV)"`
# after moving this file.
_ROOT_ENV = Path(__file__).resolve().parents[4] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=str(_ROOT_ENV), extra="ignore")

    api_host: str = "0.0.0.0"  # nosec B104 - intentional: must be reachable from other containers/host
    api_port: int = 8000
    api_cors_origins: str = "http://localhost:3000"
    # gds_api.worker_main's own /metrics HTTP server (see its module docstring for why
    # it needs one separate from main.py's).
    worker_metrics_port: int = 8001

    # NOTE: default hosts are 127.0.0.1, not "localhost". docker-compose.yml publishes
    # every port on 127.0.0.1 only; resolving "localhost" can try ::1 (IPv6) first and
    # fall back after a multi-second delay, which blows past the 3s health-check timeout
    # under load. Use 127.0.0.1 explicitly to avoid that resolution cost entirely.
    postgres_host: str = "127.0.0.1"
    postgres_port: int = 5432
    postgres_db: str = "gds"
    postgres_user: str = "gds"
    postgres_password: str = "gds_dev_password"

    redis_host: str = "127.0.0.1"
    redis_port: int = 6379

    neo4j_host: str = "127.0.0.1"
    neo4j_bolt_port: int = 7687
    neo4j_user: str = "neo4j"
    neo4j_password: str = "gds_dev_password"

    qdrant_host: str = "127.0.0.1"
    qdrant_http_port: int = 6333

    temporal_host: str = "127.0.0.1"
    temporal_port: int = 7233

    nats_host: str = "127.0.0.1"
    nats_port: int = 4222

    minio_host: str = "127.0.0.1"
    minio_api_port: int = 9000
    minio_root_user: str = "gds_admin"
    minio_root_password: str = "gds_dev_password"
    minio_evidence_bucket: str = "gds-evidence"

    # No default: a missing secret must fail loudly at startup, not silently fall back to
    # a value that would be identical across every install of this project. start-gds.ps1
    # generates a random one into .env the first time it creates that file.
    jwt_secret_key: str
    jwt_access_token_minutes: int = 15
    jwt_refresh_token_days: int = 7
    # False for local http. Set true (via .env) once this is ever served over https.
    cookie_secure: bool = False

    # Phase 2 bootstrap admin — scripts/seed.py only. Never hardcode credentials.
    seed_admin_email: str | None = None
    seed_admin_password: str | None = None

    # Phase 3: optional (not required-without-default like jwt_secret_key) because most
    # of this app must keep working while this is unset — model_router raises its own
    # clear error only when a call actually needs it, rather than failing Settings() for
    # every route in the app.
    anthropic_api_key: str | None = None
    model_router_default_model: str = "claude-sonnet-5"

    # Phase 18: same optional-with-clear-error-at-call-time pattern as anthropic_api_key
    # above - gds_api.engineering.openai_provider raises its own real ProviderError only
    # when a session actually needs it.
    openai_api_key: str | None = None
    # Real, live-confirmed model id (queried via client.models.list() against the real
    # OpenAI API this session, 2026-07-18) - the latest "-codex" tagged model available.
    engineering_openai_model: str = "gpt-5.3-codex"

    # Phase 9: when true, gds_api.model_router.complete() returns a canned response
    # instead of calling the real Anthropic API - used only by load-tests/k6-missions.js
    # to exercise real DB/Temporal/Tool-Gateway concurrency under load without paying
    # real per-call cost for a bounded but real-volume POST /missions load test. Must
    # never be true outside a load-testing run - default false, and the CostRecord it
    # writes is unmistakably labeled (provider="anthropic-load-test-stub", zero cost),
    # never confusable with real usage data.
    load_test_mode: bool = False

    @property
    def cors_origins_list(self) -> list[str]:
        return [origin.strip() for origin in self.api_cors_origins.split(",") if origin.strip()]

    @property
    def postgres_dsn(self) -> str:
        return (
            f"postgresql://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def postgres_async_dsn(self) -> str:
        return (
            f"postgresql+asyncpg://{self.postgres_user}:{self.postgres_password}"
            f"@{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )

    @property
    def neo4j_uri(self) -> str:
        return f"bolt://{self.neo4j_host}:{self.neo4j_bolt_port}"

    @property
    def qdrant_url(self) -> str:
        return f"http://{self.qdrant_host}:{self.qdrant_http_port}"

    @property
    def minio_url(self) -> str:
        return f"http://{self.minio_host}:{self.minio_api_port}"


settings = Settings()
