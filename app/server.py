"""Server skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json
import os
import hashlib
import hmac
import mysql.connector


# -------------------------------------------------------
#  MYSQL CONFIG
# -------------------------------------------------------
MYSQL_CONFIG = {
    'host': '127.0.0.1',
    'user': 'securechat_user',   # ← use new user
    'password': 'strongpassword', # ← password you set
    'database': 'securechat',
    'raise_on_warnings': True,
    'use_pure': True
}


def get_db_conn():
    return mysql.connector.connect(**MYSQL_CONFIG)


# -------------------------------------------------------
#  REGISTER USER
# -------------------------------------------------------
def register_user(email: str, username: str, password: str):
    salt = os.urandom(16)
    pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

    try:
        conn = get_db_conn()
        cur = conn.cursor()
        sql = "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)"
        cur.execute(sql, (email, username, salt, pwd_hash))
        conn.commit()
        cur.close()
        conn.close()
        return True, 'registered'
    except mysql.connector.IntegrityError:
        return False, 'username already exists'
    except Exception as e:
        return False, f'database error: {e}'


# -------------------------------------------------------
#  VERIFY LOGIN
# -------------------------------------------------------
def verify_login(username: str, password: str):
    try:
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT salt, pwd_hash FROM users WHERE username = %s", (username,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if not row:
            return False, 'no such user'

        salt, stored_hash = row
        computed_hash = hashlib.sha256(salt + password.encode()).hexdigest()

        if hmac.compare_digest(computed_hash, stored_hash):
            return True, 'ok'
        else:
            return False, 'invalid password'

    except Exception as e:
        return False, f'database error: {e}'


# -------------------------------------------------------
#  MAIN SERVER LOGIC
# -------------------------------------------------------
def main():
    HOST = "0.0.0.0"
    PORT = 5000

    print("[SERVER] Listening on port 5000...")

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen(5)

    while True:
        conn, addr = s.accept()
        print(f"[+] Client connected: {addr}")

        try:
            raw = conn.recv(4096).decode()
            if not raw:
                conn.close()
                continue

            print("[RAW DATA]:", raw)

            msg = json.loads(raw)
            action = msg.get("action")

            # ---------------------------
            # HANDLE REGISTRATION
            # ---------------------------
            if action == "register":
                ok, resp = register_user(
                    msg["email"],
                    msg["username"],
                    msg["password"]
                )
                conn.send(resp.encode())

            # ---------------------------
            # HANDLE LOGIN
            # ---------------------------
            elif action == "login":
                ok, resp = verify_login(
                    msg["username"],
                    msg["password"]
                )
                conn.send(resp.encode())

            else:
                conn.send(b"invalid action")

        except Exception as e:
            print("Error:", e)
            conn.send(b"server error")

        conn.close()


if __name__ == "__main__":
    main()
