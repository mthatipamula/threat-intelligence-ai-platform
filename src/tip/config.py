"""Settings from environment variables and .env (never printed)."""

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=ROOT / ".env", extra="ignore")

    postgres_password: str = ""
    database_url: str = ""
    abusech_auth_key: str = ""
    anthropic_api_key: str = ""  # live investigations; empty = the SDK's own lookup (env var or `ant auth login`)
    watch_domains: str = "coinbase.com"
    data_dir: Path = ROOT / "data"

    @property
    def dsn(self) -> str:
        if self.database_url:
            return self.database_url
        if not self.postgres_password:
            raise RuntimeError("No database configured: run ./scripts/init-env.sh, or set DATABASE_URL")
        return f"postgresql://tip:{self.postgres_password}@localhost:5433/tip"

    @property
    def cache_dir(self) -> Path:
        path = self.data_dir / "cache"
        path.mkdir(parents=True, exist_ok=True)
        return path

    @property
    def logs_db(self) -> Path:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "logs.duckdb"

    @property
    def watched_domains(self) -> list[str]:
        return [d.strip().lower() for d in self.watch_domains.split(",") if d.strip()]


@lru_cache
def settings() -> Settings:
    return Settings()
