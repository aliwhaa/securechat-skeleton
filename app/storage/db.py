#!/usr/bin/env python3
"""
app/storage/db.py

MySQL user store for SecureChat.

Responsibilities:
- Initialize database schema (users table).
- Add new user with 16-byte random salt and sha256(salt||password) stored as hex.
- Retrieve user by username or email.
- Verify login credentials (constant-time compare).

Usage (CLI):
    python -m app.storage.db --init
"""

import os
import argparse
import logging
import mysql.connector
from mysql.connector import errorcode
import secrets
import hashlib
import hmac

# Read DB connection settings from environment variables (use .env in project root)
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "scuser")
DB_PASSWORD = os.getenv("DB_PASSWORD", "scpass")
DB_NAME = os.getenv("DB_NAME", "securechat")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def get_conn():
    """
    Open and return a new MySQL connection object.
    Caller is responsible for closing the connection/cursor.
    """
    return mysql.connector.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        autocommit=False,
    )


def init_db():
    """
    Create the users table if it does not exist.
    Table schema:
      users(email VARCHAR, username VARCHAR UNIQUE, salt VARBINARY(16), pwd_hash CHAR(64))
    """
    create_table_sql = """
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      email VARCHAR(255) NOT NULL,
      username VARCHAR(255) NOT NULL UNIQUE,
      salt VARBINARY(16) NOT NULL,
      pwd_hash CHAR(64) NOT NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    conn = None
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            port=DB_PORT,
            user=DB_USER,
            password=DB_PASSWORD,
            autocommit=True,
        )
        cur = conn.cursor()
        cur.execute(f"CREATE DATABASE IF NOT EXISTS `{DB_NAME}` DEFAULT CHARACTER SET 'utf8mb4'")
        cur.execute(f"USE `{DB_NAME}`")
        cur.execute(create_table_sql)
        logger.info("Initialized database and ensured users table exists.")
    except mysql.connector.Error as e:
        logger.exception("Error initializing database: %s", e)
        raise
    finally:
        if conn:
            conn.close()


def _hash_password(salt: bytes, password: str) -> str:
    """
    Compute hex SHA256(salt || password_bytes).
    Returns lower-case hex string of length 64.
    """
    if not isinstance(salt, (bytes, bytearray)) or len(salt) != 16:
        raise ValueError("salt must be 16 bytes")
    if not isinstance(password, str):
        raise TypeError("password must be str")
    pwd_bytes = password.encode("utf-8")
    h = hashlib.sha256(salt + pwd_bytes).hexdigest()
    return h


def create_user(email: str, username: str, password: str) -> bool:
    """
    Create a new user.
    - Generates a 16-byte random salt (os.urandom via secrets.token_bytes).
    - Computes pwd_hash = sha256(salt || password) as hex.
    - Inserts into users table.

    Returns True on success, False if username/email already exists.
    """
    salt = secrets.token_bytes(16)
    pwd_hash = _hash_password(salt, password)

    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
        cur.execute(sql, (email, username, salt, pwd_hash))
        conn.commit()
        logger.info("Created user %s", username)
        return True
    except mysql.connector.IntegrityError as e:
        # Unique constraint / duplicate username
        logger.warning("Could not create user (possible duplicate): %s", e)
        if conn:
            conn.rollback()
        return False
    except Exception:
        logger.exception("Unexpected error creating user")
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


def get_user_by_username(username: str):
    """
    Return a tuple (email, username, salt_bytes, pwd_hash_hex) or None if not found.
    """
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        if row:
            email, username, salt, pwd_hash = row
            return email, username, salt, pwd_hash
        return None
    finally:
        if conn:
            conn.close()


def get_user_by_email(email: str):
    """
    Return a tuple (email, username, salt_bytes, pwd_hash_hex) or None if not found.
    """
    conn = None
    try:
        conn = get_conn()
        cur = conn.cursor()
        cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE email = %s", (email,))
        row = cur.fetchone()
        if row:
            email, username, salt, pwd_hash = row
            return email, username, salt, pwd_hash
        return None
    finally:
        if conn:
            conn.close()


def verify_user_credentials(username_or_email: str, password: str) -> bool:
    """
    Verify the provided credentials. Accepts either username or email as identifier.
    Uses constant-time comparison to avoid timing leaks.
    Returns True if credentials valid, False otherwise.
    """
    record = get_user_by_username(username_or_email)
    if record is None:
        record = get_user_by_email(username_or_email)
    if record is None:
        logger.info("User not found: %s", username_or_email)
        return False

    email, username, salt, stored_hash = record
    computed_hash = _hash_password(salt, password)

    # constant-time compare
    if hmac.compare_digest(computed_hash, stored_hash):
        logger.info("User %s authenticated successfully", username)
        return True
    else:
        logger.info("Authentication failed for user %s", username)
        return False


# CLI entrypoint to initialize DB
def _cli():
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true", help="Initialize database and create tables")
    args = parser.parse_args()
    if args.init:
        init_db()


if __name__ == "__main__":
    _cli()

