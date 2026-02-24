import os
import sqlite3
from typing import Optional, Dict, Any
from werkzeug.security import generate_password_hash, check_password_hash


def get_db_path() -> str:
    return os.getenv("DATABASE_PATH", "/data/notely.db")


def get_db_connection(db_path: str):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = get_db_connection(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS notes (
                user_id INTEGER PRIMARY KEY,
                content TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def create_user(db_path: str, username: str, password: str) -> Optional[int]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            return None
        password_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, datetime('now'))",
            (username, password_hash),
        )
        conn.commit()
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        return row["id"] if row else None
    finally:
        conn.close()


def verify_user(db_path: str, username: str, password: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            return None
        if not check_password_hash(row["password_hash"], password):
            return None
        return {"id": row["id"], "username": row["username"]}
    finally:
        conn.close()


def get_user_by_id(db_path: str, user_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id, username FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return {"id": row["id"], "username": row["username"]}
    finally:
        conn.close()


def get_user_by_username(db_path: str, username: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id, username FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            return None
        return {"id": row["id"], "username": row["username"]}
    finally:
        conn.close()


def get_note_by_username(db_path: str, username: str) -> Optional[str]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        if user is None:
            return None
        cur = conn.execute("SELECT content FROM notes WHERE user_id = ?", (user["id"],))
        row = cur.fetchone()
        if row is None:
            return ""
        return row["content"]
    finally:
        conn.close()


def upsert_note_for_user(db_path: str, user_id: int, content: str):
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT user_id FROM notes WHERE user_id = ?", (user_id,))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO notes (user_id, content, updated_at) VALUES (?, ?, datetime('now'))",
                (user_id, content),
            )
        else:
            conn.execute(
                "UPDATE notes SET content = ?, updated_at = datetime('now') WHERE user_id = ?",
                (content, user_id),
            )
        conn.commit()
    finally:
        conn.close()


def ensure_admin(db_path: str):
    admin_password = os.getenv("ADMIN_PASSWORD", "admin")
    flag = os.getenv("FLAG", "ctf{Testing_Flag}")
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id FROM users WHERE username = 'admin'")
        row = cur.fetchone()
        if row is None:
            password_hash = generate_password_hash(admin_password)
            conn.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES ('admin', ?, datetime('now'))",
                (password_hash,),
            )
            conn.commit()
            cur = conn.execute("SELECT id FROM users WHERE username = 'admin'")
            row = cur.fetchone()
        if row is not None:
            admin_id = row["id"]
            cur = conn.execute("SELECT user_id FROM notes WHERE user_id = ?", (admin_id,))
            message = f"My life savings literally depend on the following key. I must never lose it: {flag}"
            if cur.fetchone() is None:
                conn.execute(
                    "INSERT INTO notes (user_id, content, updated_at) VALUES (?, ?, datetime('now'))",
                    (admin_id, message),
                )
            else:
                conn.execute(
                    "UPDATE notes SET content = ?, updated_at = datetime('now') WHERE user_id = ?",
                    (message, admin_id),
                )
            conn.commit()
    finally:
        conn.close()
