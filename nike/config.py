"""Environment-driven config for the Nike.com.br purchase bot."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from zoneinfo import ZoneInfo


def _env(name: str, default: str = "") -> str:
    val = os.environ.get(name, default).strip()
    # Strip surrounding quotes if someone exported with extra quoting
    # (e.g. NIKE_PASSWORD="'value'")
    for q in ("'", '"'):
        if len(val) >= 2 and val[0] == q and val[-1] == q:
            val = val[1:-1]
            break
    return val


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env(name, "").lower()
    if not raw:
        return default
    return raw in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    raw = _env(name, "")
    return int(raw) if raw else default


@dataclass
class NikeConfig:
    email: str
    password: str
    product_url: str
    product_size: str
    drop_time: datetime | None
    timezone: str
    refresh_interval_ms: int
    max_runtime_minutes: int
    pre_login_minutes: int
    dry_run: bool
    headless: bool
    user_agent: str
    storage_state_path: str

    @property
    def tz(self) -> ZoneInfo:
        return ZoneInfo(self.timezone)

    def drop_time_local(self) -> datetime | None:
        if self.drop_time is None:
            return None
        if self.drop_time.tzinfo is None:
            return self.drop_time.replace(tzinfo=self.tz)
        return self.drop_time.astimezone(self.tz)

    def validate(self) -> list[str]:
        errors = []
        if not self.email:
            errors.append("NIKE_EMAIL is required")
        if not self.password:
            errors.append("NIKE_PASSWORD is required")
        if not self.product_url:
            errors.append("NIKE_PRODUCT_URL is required")
        if not self.product_url.startswith("https://www.nike.com.br"):
            errors.append("NIKE_PRODUCT_URL must be on https://www.nike.com.br")
        if not self.product_size:
            errors.append("NIKE_PRODUCT_SIZE is required (e.g. '42', '10.5')")
        return errors


def load_config() -> NikeConfig:
    drop_raw = _env("NIKE_DROP_TIME", "")
    drop_time: datetime | None = None
    if drop_raw:
        drop_time = datetime.fromisoformat(drop_raw)

    return NikeConfig(
        email=_env("NIKE_EMAIL"),
        password=_env("NIKE_PASSWORD"),
        product_url=_env("NIKE_PRODUCT_URL"),
        product_size=_env("NIKE_PRODUCT_SIZE"),
        drop_time=drop_time,
        timezone=_env("NIKE_TIMEZONE", "America/Sao_Paulo"),
        refresh_interval_ms=_env_int("NIKE_REFRESH_INTERVAL_MS", 800),
        max_runtime_minutes=_env_int("NIKE_MAX_RUNTIME_MINUTES", 15),
        pre_login_minutes=_env_int("NIKE_PRE_LOGIN_MINUTES", 5),
        dry_run=_env_bool("NIKE_DRY_RUN", True),
        headless=_env_bool("NIKE_HEADLESS", True),
        user_agent=_env(
            "NIKE_USER_AGENT",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36",
        ),
        storage_state_path=_env("NIKE_STORAGE_STATE", "/tmp/nike_state.json"),
    )
