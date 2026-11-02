import hashlib
import hmac
import os
import sqlite3

SEED_USERS = [
    (1, "alice", "alice123"),
    (2, "bob", "bob123"),
]

_ITERATIONS = 200_000


def db_path() -> str:
    return os.environ.get("DB_PATH", "gateway.db")


def connect() -> sqlite3.Connection:
    conn = sqlite3.connect(db_path())
    conn.row_factory = sqlite3.Row
    return conn


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _ITERATIONS)
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        _, iterations, salt, digest = stored.split("$")
        candidate = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt), int(iterations)
        )
    except ValueError:
        return False
    return hmac.compare_digest(candidate.hex(), digest)


def init_db() -> None:
    with connect() as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS users ("
            "id INTEGER PRIMARY KEY, "
            "username TEXT NOT NULL UNIQUE, "
            "password_hash TEXT NOT NULL)"
        )
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            conn.executemany(
                "INSERT INTO users (id, username, password_hash) VALUES (?, ?, ?)",
                [(uid, name, hash_password(pw)) for uid, name, pw in SEED_USERS],
            )
    conn.close()


def get_user_by_username(username: str):
    conn = connect()
    try:
        return conn.execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?",
            (username,),
        ).fetchone()
    finally:
        conn.close()
