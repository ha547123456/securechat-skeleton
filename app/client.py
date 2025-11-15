"""Client skeleton — plain TCP; no TLS. See assignment spec."""

import socket
import json

HOST = "127.0.0.1"
PORT = 5000

def main():
    print("SecureChat Client (plain TCP)")
    
    while True:
        action = input("Action (register/login/quit): ").strip().lower()
        if action == "quit":
            break
        elif action not in ["register", "login"]:
            print("Invalid action, try again.")
            continue

        packet = {"action": action}

        if action == "register":
            packet["email"] = input("Email: ").strip()
            packet["username"] = input("Username: ").strip()
            packet["password"] = input("Password: ").strip()
        elif action == "login":
            packet["username"] = input("Username: ").strip()
            packet["password"] = input("Password: ").strip()

        try:
            # Connect to server
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((HOST, PORT))

            # Send JSON as bytes
            s.send(json.dumps(packet).encode())

            # Receive reply
            reply = s.recv(4096).decode()
            print("[SERVER REPLY]:", reply)

            s.close()
        except Exception as e:
            print("Connection error:", e)


if __name__ == "__main__":
    main()
