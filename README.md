## 🛡️ SecureChat: My CIAnR Console Messenger Project

**Course:** Information Security (FAST–NUCES) | **Semester:** Fall 2025

This project, Assignment \#2, is a console-based secure chat application I built. The goal was to implement the core security pillars—**Confidentiality, Integrity, Authenticity, and Non-Repudiation (CIANR)**—entirely at the application layer, without relying on built-in OS/network security like TLS/SSL.

I've detailed the protocol, setup, and compliance rules below.

-----

### 📌 My CIAnR Security Protocol

The entire system is based on cryptographic primitives and established protocols, chained together to guarantee end-to-end security.

| Security Goal | Implementation Details |
| :--- | :--- |
| **Authenticity (Peer)** | **X.509 Certificates** exchanged and verified against a trusted **Root CA** during the initial handshake. |
| **Confidentiality (Session)** | **Diffie–Hellman Key Exchange** to securely derive a shared, ephemeral **AES-128 session key**. |
| **Confidentiality (Data)** | **AES-128 Encryption** (using PKCS\#7 padding) applied to all chat messages. |
| **Integrity & Authenticity (Data)** | A **SHA-256** hash of the message contents (`seqno \|\| ts \|\| ciphertext`) is generated and signed using the sender's **RSA** private key (PKCS\#1 v1.5). |
| **Replay Defense** | Every message includes a strictly increasing **sequence number (`seqno`)** and a **timestamp (`ts`)**. |
| **Non-Repudiation** | At session end, both sides sign a **SHA-256 hash of the full session transcript**, creating a verifiable **Signed Receipt**. |

-----

### 📂 Project Structure (The Codebase)

```
securechat-skeleton/
│
├── client/
│   ├── client.py               # Main client logic (handshake, DH, chat loop, receipt generation)
│   └── transcript_client.txt   # Log of all message metadata
│
├── server/
│   ├── server.py               # Main server logic (listening, certificate handling, DB access)
│   └── transcript_server.txt   # Log of all message metadata
│
├── scripts/
│   ├── gen_ca.py               # Script for generating the Root CA (my own trusted authority)
│   ├── gen_cert.py             # Script to generate Server/Client certificates (signed by my CA)
│   └── utils.py                # Crypto functions (hashing, signing, AES) and network utilities
│
├── certs/                      # Generated keys and certificates (Ignored by Git!)
│
└── database/
    └── schema.sql              # MySQL schema for user authentication data
```

-----

### ⚙️ Prerequisites & Setup

#### 1\. Python Dependencies

```bash
pip install cryptography pycryptodome mysql-connector-python
```

#### 2\. MySQL Database Setup

The server uses MySQL for storing user registration data (username, salt, and password hash).

1.  Start MySQL service.
2.  Execute the schema creation:
    ```sql
    CREATE DATABASE securechat;
    USE securechat;

    CREATE TABLE users (
        email VARCHAR(100),
        username VARCHAR(50) UNIQUE,
        salt VARBINARY(16),
        pwd_hash CHAR(64)
    );
    ```
3.  Ensure the credentials in `server/server.py` match your setup (e.g., `user = "root"`, `password = "your_password"`).

-----

### 🚀 Execution Flow

#### 1\. Certificate Generation

This step creates all necessary keys and certificates, signed by the custom Root CA.

```bash
# Navigate to scripts directory first
cd scripts/
python gen_ca.py
python gen_cert.py server
python gen_cert.py client
```

#### 2\. Start Server

The server handles certificate validation, DH key exchange, and user login/registration.

```bash
cd ../server/
python server.py
# Server output should show: "[SERVER] Listening on port 5000..."
```

#### 3\. Start Client

The client connects, verifies the server, performs DH, and prompts for login/registration.

```bash
cd ../client/
python client.py
# Client output should show: "[+] Connected to server" and handshake progress.
```

#### 4\. Secure Chat Session

Once established, messages are exchanged in the secure data format:

```json
{
  "type": "msg",
  "seqno": n,                  // Replay defense
  "ts": "<unix_ms>",           // Replay defense
  "ct": "<AES ciphertext>",    // Confidentiality
  "sig": "<RSA signature>"     // Integrity & Authenticity
}
```

#### 5\. Non-Repudiation Receipt

After closing the chat, two files are created to prove what was communicated:

  * `client_receipt.json`
  * `server_receipt.json`

These contain the final signed hash of the session transcript.

-----

### 🧪 Testing for Security Guarantees (Evidence for Report)

| Test Case | Expected Outcome | Security Feature Tested |
| :--- | :--- | :--- |
| **Wireshark Monitor** | Only encrypted data (ciphertext) visible on `tcp.port == 5000`. | **Confidentiality** |
| **Invalid Certificate** | Server prints: `BAD CERT — rejecting connection`. | **Authenticity (CA Trust)** |
| **Ciphertext Tampering** | Receiving party prints: `SIG FAIL`. | **Integrity** |
| **Re-sending Old Message** | Receiving party prints: `REPLAY — old seqno detected`. | **Replay Defense** |
| **Offline Receipt Check** | Verification of the receipt's RSA signature using the sender's public key is successful. | **Non-Repudiation** |

-----

### 📝 Assignment Compliance

I made sure to adhere strictly to the rules provided for this assignment:

  * **❌ No SSL/TLS allowed.** (All crypto is manual/application layer).
  * **❌ No committing private keys, salts, or DB passwords.**
  * **❌ No chat message storage in MySQL.** (Only user authentication data is stored).
  * **✅ Used only AES block cipher.**
  * **✅ Used RSA signatures (PKCS\#1 v1.5).**
  * **✅ Used SHA-256 for all hashing.**
  * **✅ At least 10 meaningful Git commits.** (Demonstrating development process).

-----

### 🧑‍💻 Author

Tooba Ali
FAST–NUCES Islamabad | Information Security | Fall 2025
