"""Alembic migrations, run programmatically so the core upgrades its own DB at startup."""

from __future__ import annotations

from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy.engine import Engine

MIGRATIONS = Path(__file__).resolve().parent / "migrations"


def _ini_value(value: str) -> str:
    # Alembic stores options in a ConfigParser, which treats "%" as interpolation.
    # SQLAlchemy URL-encodes Windows drive colons ("C%3A"), so escape it.
    return value.replace("%", "%%")


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", _ini_value(str(MIGRATIONS)))
    cfg.set_main_option("sqlalchemy.url", _ini_value(url))
    return cfg


def upgrade_to_head(engine: Engine) -> None:
    cfg = alembic_config(str(engine.url))
    with engine.begin() as conn:
        cfg.attributes["connection"] = conn
        command.upgrade(cfg, "head")
