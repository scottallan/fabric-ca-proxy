import json
import base64
import hashlib
import requests

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509 import load_pem_x509_certificate

# === Config ===
CA_URL = "http://fabric-ca-server:7054/register"
CERT_PATH = "admin-cert.pem"
KEY_PATH = "admin-key.pem"

# Registration payload
payload = {
    "id": "appUser8",
    "type": "client",
    "secret": "password",
    "affiliation": "org1.department1"
}

def load_key_and_cert(cert_path, key_path):
    with open(cert_path, "rb") as f:
        cert_pem = f.read()
    with open(key_path, "rb") as f:
        key_pem = f.read()

    cert = load_pem_x509_certificate(cert_pem)
    public_key = cert.public_key()

    private_key = serialization.load_pem_private_key(
        key_pem, password=None
    )

    return cert_pem, cert, private_key

def create_auth_token(cert_pem, private_key, method, uri, body_bytes):
    b64uri = base64.b64encode(uri.encode("utf-8")).decode("ascii")
    b64body = base64.b64encode(body_bytes).decode("ascii")
    b64cert = base64.b64encode(cert_pem).decode("ascii")

    signing_string = f"{method}.{b64uri}.{b64body}.{b64cert}".encode("utf-8")
    digest = hashlib.sha256(signing_string).digest()

    signature = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    # Decode r, s
    r, s = utils.decode_dss_signature(signature)

    # Get curve order for P-256 (secp256r1)
    curve_order = int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)

    # Low-S normalization
    if s > curve_order // 2:
       s = curve_order - s

    # Re-encode signature
    normalized_signature = utils.encode_dss_signature(r, s)

    b64sig = base64.b64encode(normalized_signature).decode("ascii")
    token = f"{b64cert}.{b64sig}"
    return token

def register_client():
    method = "POST"
    uri = "/register"
    body_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    cert_pem, cert, private_key = load_key_and_cert(CERT_PATH, KEY_PATH)
    auth_token = create_auth_token(cert_pem, private_key, method, uri, body_bytes)

    headers = {
        "Authorization": auth_token,
        "User-Agent": "Go-http-client/1.1"
    }
        #"Content-Type": "application/json"

    print("Sending registration request...")
    response = requests.post(CA_URL, headers=headers, data=body_bytes)
    print("Response status:", response.status_code)
    print("Response body:", response.text)

if __name__ == "__main__":
    register_client()

