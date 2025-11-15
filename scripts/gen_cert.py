#!/usr/bin/env python3
"""
gen_cert.py
Generate server or client certificate signed by Root CA.

Usage:
    python gen_cert.py server
    python gen_cert.py client
"""

import sys
import os
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# CA files
CA_KEY_FILE = "../certs/ca.key"
CA_CERT_FILE = "../certs/ca.crt"

# Certificate validity
VALID_YEARS = 5
KEY_SIZE = 2048

def load_ca():
    with open(CA_KEY_FILE, "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(CA_CERT_FILE, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    return ca_key, ca_cert

def generate_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE)

def build_subject(name):
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Islamabad"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

def create_csr(key, subject):
    return x509.CertificateSigningRequestBuilder().subject_name(subject).sign(
        key, hashes.SHA256()
    )

def sign_csr(csr, ca_key, ca_cert):
    now = datetime.utcnow()
    cert = x509.CertificateBuilder(
    ).subject_name(
        csr.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now - timedelta(minutes=1)
    ).not_valid_after(
        now + timedelta(days=VALID_YEARS*365)
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).sign(private_key=ca_key, algorithm=hashes.SHA256())
    return cert

def save_key(key, filename):
    with open(filename, "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption()
        ))
    os.chmod(filename, 0o600)
    print(f"Saved private key: {filename}")

def save_cert(cert, filename):
    with open(filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(filename, 0o644)
    print(f"Saved certificate: {filename}")

def main():
    if len(sys.argv) != 2 or sys.argv[1] not in ["server", "client"]:
        print("Usage: python gen_cert.py server|client")
        sys.exit(1)

    name = sys.argv[1]
    key_file = f"../certs/{name}.key"
    cert_file = f"../certs/{name}.crt"

    ca_key, ca_cert = load_ca()
    key = generate_key()
    subject = build_subject(f"SecureChat {name.capitalize()}")
    csr = create_csr(key, subject)
    cert = sign_csr(csr, ca_key, ca_cert)

    save_key(key, key_file)
    save_cert(cert, cert_file)
    print(f"{name.capitalize()} certificate generation complete.")

if __name__ == "__main__":
    main()
