#!/usr/bin/env python3
import socket, json, os, hashlib, time
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding

def a1(sock, data: bytes):
    sock.sendall(len(data).to_bytes(4, "big") + data)

def a2(sock):
    x = sock.recv(4)
    if not x or len(x) < 4:
        raise ConnectionError("nohdr")
    n = int.from_bytes(x, "big")
    d = b""
    while len(d) < n:
        p = sock.recv(n - len(d))
        if not p:
            raise ConnectionError("closed")
        d += p
    return d

def b1(k: bytes, t: str) -> bytes:
    v = os.urandom(16)
    c = AES.new(k, AES.MODE_CBC, v)
    m = c.encrypt(pad(t.encode(), 16))
    return v + m

def b2(k: bytes, ctt: bytes) -> str:
    v = ctt[:16]
    m = ctt[16:]
    c = AES.new(k, AES.MODE_CBC, v)
    return unpad(c.decrypt(m), 16).decode()

DIR = os.path.join(os.path.dirname(__file__), "..", "certs")
CK = os.path.join(DIR, "client.key")
SC = os.path.join(DIR, "server.crt")

def c1(p):
    with open(p, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def c2(p):
    with open(p, "rb") as f:
        c = x509.load_pem_x509_certificate(f.read())
    return c.public_key()

def c3(pkey, d: bytes) -> bytes:
    return pkey.sign(d, asym_padding.PKCS1v15(), hashes.SHA256())

def c4(pub, d: bytes, s: bytes) -> bool:
    try:
        pub.verify(s, d, asym_padding.PKCS1v15(), hashes.SHA256())
        return True
    except:
        return False

PHEX = ("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A63A3620FFFFFFFFFFFFFFFF")
PP = int(PHEX, 16)
GG = 2

HST, PRT = "127.0.0.1", 5000
cl_priv = c1(CK)
srv_pub = c2(SC)

def d1(x):
    if x == "register":
        e = input("Email: ").strip()
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        return {"action": "register", "email": e, "username": u, "password": p}
    else:
        u = input("Username: ").strip()
        p = input("Password: ").strip()
        return {"action": "login", "username": u, "password": p}

def main():
    print("SecureChat client obfuscated")
    while True:
        z = input("Action (register/login/quit): ").strip().lower()
        if z == "quit":
            break
        if z not in ("register", "login"):
            print("Invalid action")
            continue

        pkt = d1(z)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((HST, PRT))

        with open(os.path.join(DIR, "client.crt"), "rb") as f:
            cc = f.read()
        a1(s, cc)

        pr = int.from_bytes(os.urandom(32), "big")
        pu = pow(GG, pr, PP)
        s.send(str(pu).encode())

        sp = int(s.recv(8192).decode())
        sh = pow(sp, pr, PP)
        shb = sh.to_bytes((sh.bit_length() + 7) // 8 or 1, "big")
        k = hashlib.sha256(shb).digest()[:16]
        print("[+] DH key OK")

        a1(s, b1(k, json.dumps(pkt)))
        rr = a2(s)
        res = b2(k, rr)
        print("[SERVER]:", res)

        if z == "login" and res.strip().upper() == "OK":
            print("You can send messages. Type 'quit' to exit.")
            q = 0
            T = []

            while True:
                t = input("Enter message: ")
                if t.lower() == "quit":
                    print("Logout…")
                    break

                q += 1
                tt = int(time.time())
                msg = {"seqno": q, "ts": tt, "text": t}

                raw = json.dumps(msg, separators=(",", ":"), sort_keys=True).encode()
                sg = c3(cl_priv, raw)
                msg["sig"] = sg.hex()

                a1(s, b1(k, json.dumps(msg)))
                T.append(msg)

                enc = a2(s)
                try:
                    dec = b2(k, enc)
                except Exception as e:
                    print("[!] decrypt fail:", e)
                    break

                j = json.loads(dec)
                sg_hex = j.pop("sig", "")
                sg_b = bytes.fromhex(sg_hex) if sg_hex else b""
                rv = json.dumps(j, separators=(",", ":"), sort_keys=True).encode()

                if c4(srv_pub, rv, sg_b):
                    print(f"[SERVER]: {j.get('text')} (OK sig)")
                    j["sig"] = sg_hex
                    T.append(j)
                else:
                    print("[!] bad server sig")

            with open("client_transcript.txt", "w") as f:
                for m in T:
                    f.write(json.dumps(m, separators=(",", ":")) + "\n")

        s.close()

if __name__ == "__main__":
    main()
