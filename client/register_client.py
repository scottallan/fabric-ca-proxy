import os
import json
import base64
import hashlib
import requests

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

# === Config ===
#CA_URL = "https://fabric-ca-server:7054/register"  # Update this if needed
CA_URL = "http://fabric-ca-server:5002/proxy/register?RequestId=TICKET-APPROVED"  # Update this if needed
CERT_PATH = "admin-cert.pem"
KEY_PATH = "admin-key.pem"

PAYLOAD_PATH = "register_request.json"


# === Functions ===

def load_payload(path):
   if not os.path.exists(path):
      raise FileNotFoundError(f"Missing payload file: {path}")
   with open(path, "r") as f:
      return json.load(f)

def load_key_and_cert(cert_path, key_path):
    with open(cert_path, "rb") as f:
        cert_pem = f.read()
    with open(key_path, "rb") as f:
        key_pem = f.read()

    private_key = serialization.load_pem_private_key(
        key_pem, password=None
    )

    return cert_pem, private_key

def sign_with_low_s(private_key, digest):
    signature = private_key.sign(
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )

    r, s = utils.decode_dss_signature(signature)

    # secp256r1 order
    curve_order = int('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16)

    if s > curve_order // 2:
        s = curve_order - s

    return utils.encode_dss_signature(r, s)

def create_auth_token(cert_pem, private_key, method, uri, body_bytes):
    b64uri = base64.b64encode(uri.encode("utf-8")).decode("ascii")
    b64body = base64.b64encode(body_bytes).decode("ascii")
    b64cert = base64.b64encode(cert_pem).decode("ascii")

    signing_string = f"{method}.{b64uri}.{b64body}.{b64cert}".encode("utf-8")
    digest = hashlib.sha256(signing_string).digest()

    normalized_signature = sign_with_low_s(private_key, digest)
    b64sig = base64.b64encode(normalized_signature).decode("ascii")

    return f"{b64cert}.{b64sig}"

def register_client():
    method = "POST"
    uri = "/register"
    payload = load_payload(PAYLOAD_PATH)
    body_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    cert_pem, private_key = load_key_and_cert(CERT_PATH, KEY_PATH)
    auth_token = create_auth_token(cert_pem, private_key, method, uri, body_bytes)

    headers = {
        "x-api-key": "changeme-key1",
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "User-Agent": "Go-http-client/1.1"
    }

    print("🔐 Registering client with Fabric CA...")
    response = requests.post(CA_URL, headers=headers, data=body_bytes, verify=False)

    print(f"\n🌐 Response: {response.status_code}")
    print(response.text)

if __name__ == "__main__":
    register_client()

