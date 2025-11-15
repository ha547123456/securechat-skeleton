#!/usr/bin/env python3
"""
gen_ca.py
Generate a root CA private key and self-signed certificate.
Saves to /certs/ca.key and /certs/ca.crt
"""

import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import timezone

# ---- Configuration ----
KEY_FILE = "../certs/ca.key"
CERT_FILE = "../certs/ca.crt"
KEY_SIZE = 2048
VALID_YEARS = 10
COMMON_NAME = "SecureChat Root CA"
ORGANIZATION = "SecureChat"
COUNTRY = "PK"
STATE = "Islamabad"
LOCALITY = "Islamabad"
# -----------------------

def ensure_certs_dir():
    certs_dir = os.path.dirname(KEY_FILE)
    os.makedirs(certs_dir, exist_ok=True)

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

def build_subject():
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, STATE),
        x509.NameAttribute(NameOID.LOCALITY_NAME, LOCALITY),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
    ])

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    os.chmod(filename, 0o600)
    print(f"Saved private key: {filename}")

def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(filename, 0o644)
    print(f"Saved certificate: {filename}")

def main():
    ensure_certs_dir()
    key = generate_key()
    subject = issuer = build_subject()

    now = datetime.now(timezone.utc)
    cert = x509.CertificateBuilder(
    ).subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - timedelta(minutes=1)
    ).not_valid_after(
        now + timedelta(days=VALID_YEARS*365)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=True
    ).sign(private_key=key, algorithm=hashes.SHA256())

    save_key(key, KEY_FILE)
    save_cert(cert, CERT_FILE)
    print("Root CA generation complete.")

if __name__ == "__main__":
    main()
