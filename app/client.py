import socket, json, hashlib, os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

HOST = "127.0.0.1"
PORT = 5000

p = int("""FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF""".replace("\n",""), 16)
g = 2

# AES helpers
def aes_encrypt(key, plaintext):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext.encode(), 16))

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[16:]), 16).decode()

# Verify server certificate
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

def start_client():
    print("SecureChat Client with DH + AES")

    while True:
        action = input("Action (register/login/quit): ").strip().lower()
        if action == "quit":
            break
        if action not in ["register", "login"]:
            print("Invalid action.")
            continue

        packet = {"action": action}
        if action == "register":
            packet["email"] = input("Email: ").strip()
            packet["username"] = input("Username: ").strip()
            packet["password"] = input("Password: ").strip()
        else:
            packet["username"] = input("Username: ").strip()
            packet["password"] = input("Password: ").strip()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))

            # --- 1️⃣ Send client certificate ---
            client_cert_bytes = open("../certs/client.crt", "rb").read()
            s.send(len(client_cert_bytes).to_bytes(4, "big") + client_cert_bytes)

            # --- 2️⃣ Receive server certificate and verify ---
            cert_len = int.from_bytes(s.recv(4), "big")
            server_cert_bytes = s.recv(cert_len)
            server_cert = verify_cert(server_cert_bytes, "../certs/ca.crt")
            if not server_cert:
                print("[-] Server certificate verification failed!")
                s.close()
                continue
            print("[+] Server certificate verified")

            # --- 3️⃣ Diffie-Hellman key exchange ---
            client_priv = int.from_bytes(os.urandom(32), 'big')
            client_pub = pow(g, client_priv, p)
            s.send(str(client_pub).encode())

            server_pub = int(s.recv(4096).decode())
            shared = pow(server_pub, client_priv, p)
            aes_key = hashlib.sha256(str(shared).encode()).digest()[:16]  # AES-128

            # --- 4️⃣ Encrypt registration/login packet ---
            s.send(aes_encrypt(aes_key, json.dumps(packet)))
            reply = aes_decrypt(aes_key, s.recv(4096))
            print("[SERVER]:", reply)

            # --- 5️⃣ Persistent chat loop after login ---
            if action == "login" and reply.lower() == "ok":
                print("You can now send messages. Type 'quit' to logout.")
                while True:
                    msg = input("Enter message: ")
                    if msg.lower() == "quit":
                        print("Logging out...")
                        break
                    s.send(aes_encrypt(aes_key, msg))
                    server_msg = aes_decrypt(aes_key, s.recv(4096))
                    print("[SERVER]:", server_msg)

            s.close()

        except Exception as e:
            print("Error:", e)

if __name__ == "__main__":
    start_client()
