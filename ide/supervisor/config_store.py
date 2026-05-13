"""User-level config store for the IDE, backed by SQLite.

Replaces the original JSON-based IdeConfigStore while preserving the
same public API so callers (SupervisorManager, tests) are unaffected.
"""

from __future__ import annotations

from pathlib import Path

from shared.database import DatabaseStore

from .models import ConfigStoreInfo, IdeConfig


class IdeConfigStore:
    """SQLite-backed store for IdeConfig.

    Data is persisted as key-value rows in the ``ide_config`` table.
    The ``config_path`` property now points to the SQLite database file.
    """

    def __init__(
        self,
        config_path: Path | None = None,
        *,
        db: DatabaseStore | None = None,
    ) -> None:
        if db is not None:
            self._db = db
            self._config_path = db.db_path
        elif config_path is not None:
            # config_path used to be a JSON file; now we interpret it as
            # the database path for backwards-compatible test injection.
            self._config_path = config_path
            self._db = DatabaseStore(db_path=config_path)
        else:
            self._config_path = None
            self._db = DatabaseStore()
            self._config_path = self._db.db_path

    @property
    def config_path(self) -> Path:
        return self._config_path or self._db.db_path

    @property
    def database(self) -> DatabaseStore:
        """Expose the underlying DatabaseStore for shared access."""
        return self._db

    def info(self) -> ConfigStoreInfo:
        return ConfigStoreInfo(
            path=str(self.config_path), exists=self.config_path.exists()
        )

    def load(self) -> IdeConfig:
        raw = self._db.load_kv_typed("ide_config", IdeConfig)
        if not raw:
            return IdeConfig()
        return IdeConfig.from_dict(raw)

    def save(self, config: IdeConfig) -> IdeConfig:
        self._db.save_kv("ide_config", config.to_dict())
        return config

    def update(self, **updates: object) -> IdeConfig:
        current = self.load().to_dict()
        current.update(updates)
        return self.save(IdeConfig.from_dict(current))
