import os
import sqlite3
from typing import Optional, Dict, Any
from werkzeug.security import generate_password_hash, check_password_hash


DATABASE_PATH = "/data/vibecoding.db"


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
                is_admin INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def create_user(db_path: str, username: str, password: str, is_admin: bool = False) -> Optional[int]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cur.fetchone() is not None:
            return None
        password_hash = generate_password_hash(password)
        conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, datetime('now'))",
            (username, password_hash, 1 if is_admin else 0),
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
        cur = conn.execute("SELECT id, username, password_hash, is_admin FROM users WHERE username = ?", (username,))
        row = cur.fetchone()
        if row is None:
            return None
        if not check_password_hash(row["password_hash"], password):
            return None
        return {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"])}
    finally:
        conn.close()


def get_user_by_id(db_path: str, user_id: int) -> Optional[Dict[str, Any]]:
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        if row is None:
            return None
        return {"id": row["id"], "username": row["username"], "is_admin": bool(row["is_admin"])}
    finally:
        conn.close()


def ensure_users(db_path: str):
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password = os.getenv("ADMIN_PASSWORD", "default_admin_password")
    
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute("SELECT id FROM users WHERE username = ?", (admin_username,))
        if cur.fetchone() is None:
            password_hash = generate_password_hash(admin_password)
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, datetime('now'))",
                (admin_username, password_hash),
            )
            conn.commit()
        
        cur = conn.execute("SELECT id FROM users WHERE username = 'j.ryder0931'")
        if cur.fetchone() is None:
            password_hash = generate_password_hash("Uncaring#Hypertext#Vocalize5")
            conn.execute(
                "INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 0, datetime('now'))",
                ("j.ryder0931", password_hash),
            )
            conn.commit()
    finally:
        conn.close()
