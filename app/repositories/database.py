from __future__ import annotations

import os
from pathlib import Path

import aiosqlite


class Database:
    """Owns the SQLite connection and schema lifecycle."""

    def __init__(self, path: str) -> None:
        self.path = path
        self.connection: aiosqlite.Connection | None = None

    async def init(self) -> None:
        directory = Path(self.path).parent
        if str(directory) not in ("", "."):
            os.makedirs(directory, exist_ok=True)
        self.connection = await aiosqlite.connect(self.path)
        self.connection.row_factory = aiosqlite.Row
        await self.connection.execute("PRAGMA journal_mode=WAL")
        await self.connection.execute("PRAGMA foreign_keys=ON")
        await self._create_schema()

    def conn(self) -> aiosqlite.Connection:
        if self.connection is None:
            raise RuntimeError("Database has not been initialized")
        return self.connection

    async def _create_schema(self) -> None:
        await self.conn().executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                telegram_id INTEGER PRIMARY KEY,
                username TEXT,
                first_name TEXT,
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER NOT NULL,
                command TEXT NOT NULL,
                input_hash TEXT,
                threat_level TEXT,
                summary TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
            );

            CREATE INDEX IF NOT EXISTS idx_history_user_created
            ON history(telegram_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS analytics_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                telegram_id INTEGER,
                event_name TEXT NOT NULL,
                metadata TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_analytics_event_created
            ON analytics_events(event_name, created_at DESC);

            CREATE TABLE IF NOT EXISTS iocs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                indicator_type TEXT NOT NULL,
                indicator_value TEXT NOT NULL,
                first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                total_observations INTEGER NOT NULL DEFAULT 1,
                cumulative_risk_score INTEGER NOT NULL DEFAULT 0,
                UNIQUE(indicator_type, indicator_value)
            );

            CREATE TABLE IF NOT EXISTS threat_observations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_id INTEGER NOT NULL,
                provider_hits INTEGER NOT NULL DEFAULT 0,
                risk_score INTEGER NOT NULL,
                confidence_score INTEGER NOT NULL,
                confidence_level TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id)
            );

            CREATE INDEX IF NOT EXISTS idx_iocs_type_value ON iocs(indicator_type, indicator_value);
            CREATE INDEX IF NOT EXISTS idx_observations_ioc ON threat_observations(ioc_id, created_at DESC);

            CREATE TABLE IF NOT EXISTS background_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                next_run_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                retry_count INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            );

            CREATE INDEX IF NOT EXISTS idx_background_jobs_ready
            ON background_jobs(status, next_run_at);

            CREATE TABLE IF NOT EXISTS ioc_relationships (
                source_ioc_id INTEGER NOT NULL,
                target_ioc_id INTEGER NOT NULL,
                relationship_type TEXT NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 50,
                first_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (source_ioc_id, target_ioc_id, relationship_type),
                FOREIGN KEY (source_ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                FOREIGN KEY (target_ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_relationships_target ON ioc_relationships(target_ioc_id);

            CREATE TABLE IF NOT EXISTS ioc_fingerprints (
                ioc_id INTEGER PRIMARY KEY,
                redirect_chain_hash TEXT,
                hosting_asn TEXT,
                metadata_hash TEXT,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS threat_families (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT
            );

            CREATE TABLE IF NOT EXISTS ioc_attributions (
                ioc_id INTEGER NOT NULL,
                family_id INTEGER NOT NULL,
                confidence INTEGER NOT NULL DEFAULT 50,
                similarity_score REAL NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (ioc_id, family_id),
                FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE,
                FOREIGN KEY (family_id) REFERENCES threat_families(id) ON DELETE CASCADE
            );
            """
        )
        await self.conn().commit()

    async def close(self) -> None:
        if self.connection is not None:
            await self.connection.close()

