#!/usr/bin/env python3
import socket, json, os, hashlib, time, traceback
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography import x509
import mysql.connector

# ---------------------------
# Length-prefix helpers
# ---------------------------
def send_raw(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)

def recv_raw(sock):
    raw_len = sock.recv(4)
    if not raw_len or len(raw_len) < 4:
        raise ConnectionError("Incomplete header")
    msg_len = int.from_bytes(raw_len, "big")
    data = b""
    while len(data) < msg_len:
        chunk = sock.recv(msg_len - len(data))
        if not chunk:
            raise ConnectionError("Connection closed during read")
        data += chunk
    return data

# ---------------------------
# AES helpers (CBC with IV prefix)
# ---------------------------
def aes_encrypt(key: bytes, plaintext: str) -> bytes:
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), 16))
    return iv + ct

def aes_decrypt(key: bytes, ciphertext: bytes) -> str:
    iv = ciphertext[:16]
    ct = ciphertext[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), 16).decode()

# ---------------------------
# RSA helpers
# ---------------------------
def load_rsa_private(path):
    with open(path, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def rsa_sign(private_key, data: bytes) -> bytes:
    return private_key.sign(data, asym_padding.PKCS1v15(), hashes.SHA256())

def rsa_verify(public_key, data: bytes, sig: bytes) -> bool:
    try:
        public_key.verify(sig, data, asym_padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False

# ---------------------------
# DB helpers (adjust credentials)
# ---------------------------
def get_db_conn():
    return mysql.connector.connect(
        host="localhost",
        user="chatuser",
        password="chatpass",
        database="securechat",
        autocommit=True
    )

# ---------------------------
# DH params (2048-bit group)
# ---------------------------
P_HEX = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF")
P = int(P_HEX, 16)
G = 2

# ---------------------------
# Config
# ---------------------------
HOST, PORT = "0.0.0.0", 5000
CERT_DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
SERVER_KEY = os.path.join(CERT_DIR, "server.key")
CA_CERT = os.path.join(CERT_DIR, "ca.crt")

server_rsa_priv = load_rsa_private(SERVER_KEY)
TRANSCRIPT_FILE = "transcript.txt"

# ---------------------------
# Client handler
# ---------------------------
def handle_client(conn, addr):
    print("[+] Connected:", addr)
    transcript = []
    last_seq = 0
    try:
        # --- Receive client certificate ---
        client_cert_bytes = recv_raw(conn)
        try:
            client_cert = x509.load_pem_x509_certificate(client_cert_bytes)
            with open(CA_CERT, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
            ca_pub = ca_cert.public_key()

            ca_pub.verify(
                client_cert.signature,
                client_cert.tbs_certificate_bytes,
                asym_padding.PKCS1v15(),
                client_cert.signature_hash_algorithm,
            )
            print("[+] Client certificate verified")
        except Exception as e:
            print("[!] BAD CERT: client not signed by CA", e)
            conn.close()
            return

        client_pub_key = client_cert.public_key()

        # --- DH (simple exchange) ---
        client_pub_str = conn.recv(8192).decode()
        client_pub = int(client_pub_str)
        server_priv = int.from_bytes(os.urandom(32), "big")
        server_pub = pow(G, server_priv, P)
        conn.send(str(server_pub).encode())

        shared = pow(client_pub, server_priv, P)
        shared_bytes = shared.to_bytes((shared.bit_length()+7)//8 or 1, "big")
        aes_key = hashlib.sha256(shared_bytes).digest()[:16]
        print("[+] DH complete, AES key established")

        # --- Expect initial encrypted (length-prefixed) register/login packet ---
        enc = recv_raw(conn)
        payload = aes_decrypt(aes_key, enc)
        packet = json.loads(payload)
        action = packet.get("action", "")

        db = get_db_conn()
        cur = db.cursor()

        if action == "register":
            email = packet.get("email", "")
            username = packet.get("username", "")
            password = packet.get("password", "")
            salt = os.urandom(16)
            pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
            try:
                cur.execute("INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                            (email, username, salt, pwd_hash))
                send_raw(conn, aes_encrypt(aes_key, "OK"))
                print(f"[+] Registered {username}")
            except mysql.connector.IntegrityError:
                send_raw(conn, aes_encrypt(aes_key, "ERR: username exists"))
                conn.close()
                return

        elif action == "login":
            username = packet.get("username", "")
            password = packet.get("password", "")
            cur.execute("SELECT salt, pwd_hash FROM users WHERE username = %s", (username,))
            row = cur.fetchone()
            if not row:
                send_raw(conn, aes_encrypt(aes_key, "ERR: no such user"))
                conn.close()
                return
            salt_db, pwd_hash_db = row
            calc_hash = hashlib.sha256(salt_db + password.encode()).hexdigest()
            if calc_hash == pwd_hash_db:
                send_raw(conn, aes_encrypt(aes_key, "OK"))
            else:
                send_raw(conn, aes_encrypt(aes_key, "ERR: bad credentials"))
                conn.close()
                return
        else:
            send_raw(conn, aes_encrypt(aes_key, "ERR: unknown action"))
            conn.close()
            return

        # --- Chat loop ---
        while True:
            try:
                enc_msg = recv_raw(conn)
            except ConnectionError:
                break

            try:
                msg_json = aes_decrypt(aes_key, enc_msg)
            except Exception as e:
                print("[!] AES decrypt failed:", e)
                break

            try:
                msg_obj = json.loads(msg_json)
            except Exception:
                print("[!] Invalid JSON")
                break

            seqno = int(msg_obj.get("seqno", 0))
            if seqno <= last_seq:
                print("[!] Replay/old seqno detected, ignoring")
                continue
            last_seq = seqno

            sig_hex = msg_obj.pop("sig", "")
            sig_bytes = bytes.fromhex(sig_hex) if sig_hex else b""
            verify_bytes = json.dumps(msg_obj, separators=(",", ":"), sort_keys=True).encode()

            if not rsa_verify(client_pub_key, verify_bytes, sig_bytes):
                print("[!] Signature verification failed for seq", seqno)
                err_obj = {"seqno": seqno, "ts": int(time.time()), "text": "ERR: bad signature"}
                err_bytes = json.dumps(err_obj, separators=(",", ":"), sort_keys=True).encode()
                err_sig = rsa_sign(server_rsa_priv, err_bytes)
                err_obj["sig"] = err_sig.hex()
                send_raw(conn, aes_encrypt(aes_key, json.dumps(err_obj)))
                continue

            msg_obj["sig"] = sig_hex
            transcript.append(msg_obj)
            print(f"[{addr}] {msg_obj.get('text')}")

            reply = {"seqno": seqno, "ts": int(time.time()), "text": f"Received: {msg_obj.get('text')}"}
            reply_bytes = json.dumps(reply, separators=(",", ":"), sort_keys=True).encode()
            reply_sig = rsa_sign(server_rsa_priv, reply_bytes)
            reply["sig"] = reply_sig.hex()
            send_raw(conn, aes_encrypt(aes_key, json.dumps(reply)))

        if transcript:
            with open(TRANSCRIPT_FILE, "w") as f:
                for m in transcript:
                    f.write(json.dumps(m, separators=(",", ":")) + "\n")
            t_hash = hashlib.sha256(open(TRANSCRIPT_FILE, "rb").read()).digest()
            receipt_sig = rsa_sign(server_rsa_priv, t_hash)
            print("[+] Transcript saved and signed (receipt hex):", receipt_sig.hex())

    except Exception as e:
        print("Error in handler:", e)
        traceback.print_exc()
    finally:
        try:
            conn.close()
        except:
            pass
        print("[+] Connection closed:", addr)

# ---------------------------
# Main
# ---------------------------
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)
    print("[SERVER] Listening on port", PORT)
    try:
        while True:
            conn, addr = sock.accept()
            handle_client(conn, addr)
    finally:
        sock.close()

if __name__ == "__main__":
    main()
