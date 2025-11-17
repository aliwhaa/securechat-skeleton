# app/server.py

import socket
import base64
import secrets
from app.common import protocol, utils
from app.crypto import pki
from app.storage import db

HOST = "0.0.0.0"
PORT = 9000

# ---- Helper functions ----
def send_json(conn, model):
    """
    Send a Pydantic model as JSON bytes.
    """
    data = model.json().encode()
    # Prefix with 4-byte length
    conn.send(len(data).to_bytes(4, "big"))
    conn.send(data)


def recv_json(conn, model_cls):
    """
    Receive a Pydantic model over socket.
    """
    length_bytes = conn.recv(4)
    if len(length_bytes) < 4:
        raise ConnectionError("Connection closed while reading length")
    length = int.from_bytes(length_bytes, "big")
    data = b""
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed during read")
        data += chunk
    return model_cls.parse_raw(data)


# ---- Server main logic ----
def handle_client(conn, addr):
    print(f"[+] Client connected: {addr}")

    # 1️⃣ Receive Hello
    hello = recv_json(conn, protocol.Hello)
    print(f"[*] Hello received with nonce: {hello.nonce}")

    # 2️⃣ Send Server Hello
    server_nonce_bytes = secrets.token_bytes(16)
    server_hello = protocol.ServerHello(
        nonce=utils.b64encode_bytes(server_nonce_bytes),
        server_cert=open("certs/server_cert.pem", "r").read()
    )
    send_json(conn, server_hello)
    print("[*] Server Hello sent with cert")

    # 3️⃣ Receive Client Register/Login
    msg_type = None
    try:
        data = conn.recv(4)
        if not data:
            print("[-] Connection closed")
            return
        # Peek at JSON type
        length = int.from_bytes(data, "big")
        raw_json = conn.recv(length)
        temp = protocol.BaseMsg.parse_raw(raw_json)
        msg_type = temp.type
    except Exception as e:
        print("[-] Failed to parse client message:", e)
        return

    # Decide if Register or Login
    if msg_type == "register":
        reg = protocol.Register.parse_raw(raw_json)
        # Check if user exists
        if db.get_user(reg.username):
            resp = protocol.RegisterResp(status="fail", reason="user exists")
            send_json(conn, resp)
            print(f"[-] Registration failed: user exists {reg.username}")
        else:
            db.create_user(reg.username, reg.pwd)
            resp = protocol.RegisterResp(status="ok")
            send_json(conn, resp)
            print(f"[+] User registered: {reg.username}")

    elif msg_type == "login":
        login = protocol.Login.parse_raw(raw_json)
        if not db.get_user(login.username):
            resp = protocol.LoginResp(status="fail", reason="user not found")
            send_json(conn, resp)
            print(f"[-] Login failed: user not found {login.username}")
        elif not db.verify_password(login.username, login.pwd):
            resp = protocol.LoginResp(status="fail", reason="wrong password")
            send_json(conn, resp)
            print(f"[-] Login failed: wrong password {login.username}")
        else:
            resp = protocol.LoginResp(status="ok")
            send_json(conn, resp)
            print(f"[+] Login successful: {login.username}")

    else:
        print("[-] Unknown message type:", msg_type)
        return

    print("[*] Control plane completed. Ready for DH / chat.")


def main():
    db.init_db()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"[+] Server listening on {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            with conn:
                handle_client(conn, addr)


if __name__ == "__main__":
    main()

