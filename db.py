import mysql.connector

def get_conn():
    return mysql.connector.connect(
        host="127.0.0.1",
        user="scuser",
        password="scpass",
        database="securechat"
    )

def insert_user(email, username, salt, pwd_hash):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
        (email, username, salt, pwd_hash)
    )
    conn.commit()
    cur.close()
    conn.close()

def get_user_by_username(username):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT email, username, salt, pwd_hash FROM users WHERE username=%s", (username,))
    row = cur.fetchone()
    cur.close()
    conn.close()
    return row

