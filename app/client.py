# app/client.py

import socket
import secrets
from app.common import protocol, utils
from app.crypto import pki
from app.storage import db

HOST = "127.0.0.1"
PORT = 9000

CLIENT_CERT_FILE = "certs/client_cert.pem"
CLIENT_KEY_FILE = "certs/client_key.pem"
CA_CERT_FILE = "certs/ca_cert.pem"

# ---- Helper functions ----
def send_json(sock, model):
    data = model.json().encode()
    sock.send(len(data).to_bytes(4, "big"))
    sock.send(data)


def recv_json(sock, model_cls):
    length_bytes = sock.recv(4)
    if len(length_bytes) < 4:
        raise ConnectionError("Connection closed while reading length")
    length = int.from_bytes(length_bytes, "big")
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Connection closed during read")
        data += chunk
    return model_cls.parse_raw(data)


# ---- Client main logic ----
def main():
    client_cert_pem = open(CLIENT_CERT_FILE, "r").read()
    ca_cert_pem = open(CA_CERT_FILE, "r").read()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((HOST, PORT))
        print("[*] Connected to server.")

        # 1️⃣ Send Hello
        nonce_bytes = secrets.token_bytes(16)
        hello = protocol.Hello(nonce=utils.b64encode_bytes(nonce_bytes))
        send_json(sock, hello)
        print("[*] Hello sent.")

        # 2️⃣ Receive Server Hello
        server_hello = recv_json(sock, protocol.ServerHello)
        print("[*] Server Hello received.")

        # 3️⃣ Validate server certificate
        valid, err = pki.validate_cert(server_hello.server_cert, ca_cert_pem, expected_cn="server")
        if not valid:
            print("[-] Server certificate invalid:", err)
            return
        print("[+] Server certificate validated.")

        # 4️⃣ Register / Login prompt
        action = input("Do you want to (r)egister or (l)ogin? ").lower()
        username = input("Username: ").strip()
        password = input("Password: ").strip()

        if action == "r":
            reg_msg = protocol.Register(username=username, pwd=password)
            send_json(sock, reg_msg)
            resp = recv_json(sock, protocol.RegisterResp)
            if resp.status != "ok":
                print("[-] Registration failed:", getattr(resp, "reason", "unknown"))
                return
            print("[+] Registration successful.")

        elif action == "l":
            login_msg = protocol.Login(username=username, pwd=password)
            send_json(sock, login_msg)
            resp = recv_json(sock, protocol.LoginResp)
            if resp.status != "ok":
                print("[-] Login failed:", getattr(resp, "reason", "unknown"))
                return
            print("[+] Login successful.")
        else:
            print("[-] Invalid option.")
            return

        print("[*] Control plane completed. Ready for DH / chat.")


if __name__ == "__main__":
    main()

