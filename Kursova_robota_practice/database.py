from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent
DATABASE_PATH = BASE_DIR / "users.db"


def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.commit()


def create_user(username: str, password_hash: str, algorithm: str) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO users (username, password_hash, algorithm)
            VALUES (?, ?, ?)
            """,
            (username, password_hash, algorithm),
        )
        connection.commit()


def get_user_by_username(username: str) -> sqlite3.Row | None:
    with get_connection() as connection:
        return connection.execute(
            """
            SELECT id, username, password_hash, algorithm, created_at
            FROM users
            WHERE username = ?
            """,
            (username,),
        ).fetchone()


def get_all_users() -> list[dict[str, Any]]:
    with get_connection() as connection:
        rows = connection.execute(
            """
            SELECT id, username, algorithm, password_hash, created_at
            FROM users
            ORDER BY created_at DESC, username ASC
            """
        ).fetchall()
    return [dict(row) for row in rows]
