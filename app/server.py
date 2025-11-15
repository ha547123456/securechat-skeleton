import socket, json, os, hashlib, hmac, mysql.connector
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

# ---------------------------
# MYSQL SETTINGS
# ---------------------------
MYSQL_CONFIG = {
    'host': '127.0.0.1',
    'user': 'securechat_user',
    'password': 'strongpassword',
    'database': 'securechat',
}

def get_db_conn():
    return mysql.connector.connect(**MYSQL_CONFIG)

# ---------------------------
# USER REGISTER / LOGIN
# ---------------------------
def register_user(email, username, password):
    salt = os.urandom(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO users(email, username, salt, pwd_hash) VALUES(%s,%s,%s,%s)",
            (email, username, salt, pwd_hash)
        )
        conn.commit()
        cur.close()
        conn.close()
        return True, "registered"
    except mysql.connector.IntegrityError:
        return False, "username already exists"
    except Exception as e:
        return False, f"db error: {e}"

def verify_login(username, password):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT salt, pwd_hash FROM users WHERE username=%s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return False, "no such user"

        salt, stored = row
        computed = hashlib.sha256(salt + password.encode()).hexdigest()
        if hmac.compare_digest(computed, stored):
            return True, "ok"
        return False, "invalid password"
    except Exception as e:
        return False, f"db error: {e}"

# ---------------------------
# AES helpers
# ---------------------------
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext.encode(), 16))

def aes_decrypt(key, ciphertext):
    if len(ciphertext) < 16:
        raise ValueError("Ciphertext too short")
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[16:]), 16).decode()

# ---------------------------
# Certificate helpers
# ---------------------------
def verify_cert(cert_bytes, ca_cert_path):
    ca_cert = x509.load_pem_x509_certificate(open(ca_cert_path, "rb").read())
    cert = x509.load_pem_x509_certificate(cert_bytes)
    try:
        ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            asym_padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        return cert
    except Exception:
        return None

# ---------------------------
# Diffie–Hellman parameters
# ---------------------------
p_hex = """FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF"""
p = int(p_hex.replace("\n", "").replace(" ", ""), 16)
g = 2

# ---------------------------
# MAIN SERVER LOOP
# ---------------------------
def main():
    HOST, PORT = "0.0.0.0", 5000
    print("[SERVER] Listening on port 5000...")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, PORT))
    sock.listen(5)

    while True:
        conn, addr = sock.accept()
        print("[+] Connected:", addr)

        try:
            # --- 1️⃣ Receive client certificate ---
            cert_len = int.from_bytes(conn.recv(4), "big")
            client_cert_bytes = conn.recv(cert_len)
            client_cert = verify_cert(client_cert_bytes, "../certs/ca.crt")
            if not client_cert:
                print("[-] Client certificate verification failed!")
                conn.close()
                continue
            print("[+] Client certificate verified")

            # --- 2️⃣ Send server certificate ---
            server_cert_bytes = open("../certs/server.crt", "rb").read()
            conn.send(len(server_cert_bytes).to_bytes(4, "big") + server_cert_bytes)

            # --- 3️⃣ Diffie–Hellman key exchange ---
            client_pub = int(conn.recv(4096).decode())
            server_priv = int.from_bytes(os.urandom(32), 'big')
            server_pub = pow(g, server_priv, p)
            conn.send(str(server_pub).encode())

            shared = pow(client_pub, server_priv, p)
            aes_key = hashlib.sha256(str(shared).encode()).digest()[:16]  # AES-128
            print("[+] DH complete, AES key established")

            # --- 4️⃣ Receive encrypted registration/login ---
            ciphertext = conn.recv(4096)
            plaintext = aes_decrypt(aes_key, ciphertext)
            msg = json.loads(plaintext)
            action = msg.get("action")

            login_success = False
            if action == "register":
                ok, resp = register_user(msg["email"], msg["username"], msg["password"])
                conn.send(aes_encrypt(aes_key, resp))

            elif action == "login":
                ok, resp = verify_login(msg["username"], msg["password"])
                conn.send(aes_encrypt(aes_key, resp))
                if ok:
                    login_success = True

            else:
                conn.send(aes_encrypt(aes_key, "invalid action"))

            # --- 5️⃣ Persistent chat loop ---
            while login_success:
                try:
                    ciphertext = conn.recv(4096)
                    if not ciphertext:
                        break
                    msg = aes_decrypt(aes_key, ciphertext)
                    print(f"[{addr}] {msg}")

                    # Echo back
                    conn.send(aes_encrypt(aes_key, f"Received: {msg}"))

                except Exception as e:
                    print("Chat error:", e)
                    break

        except Exception as e:
            print("Error:", e)

        conn.close()
        print("[+] Connection closed:", addr)


if __name__ == "__main__":
    main()
