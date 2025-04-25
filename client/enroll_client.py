import base64
import json
import requests
import argparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

OID_MAP = {
    "C": NameOID.COUNTRY_NAME,
    "ST": NameOID.STATE_OR_PROVINCE_NAME,
    "L": NameOID.LOCALITY_NAME,
    "O": NameOID.ORGANIZATION_NAME,
    "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "CN": NameOID.COMMON_NAME,
    "E": NameOID.EMAIL_ADDRESS
}

def parse_subject(subject_string, common_name):
    parts = [p for p in subject_string.strip("/").split("/") if p]
    name_attributes = []

    for part in parts:
        key, _, value = part.partition("=")
        oid = OID_MAP.get(key)
        if oid is None:
            raise ValueError(f"Unsupported subject component: {key}")
        name_attributes.append(x509.NameAttribute(oid, value))

    # Always append CN from common_name (enroll ID)
    name_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(name_attributes)

def generate_private_key():
    return ec.generate_private_key(ec.SECP256R1())

def create_csr(private_key, subject: x509.Name):
    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(private_key, hashes.SHA256())
    return csr.public_bytes(serialization.Encoding.PEM)

def build_auth_header(username, password):
    creds = f"{username}:{password}".encode("utf-8")
    return base64.b64encode(creds).decode("utf-8")

def enroll(ca_url, enroll_id, enroll_secret, output_prefix, subject_prefix, api_key):
    private_key = generate_private_key()
    subject = parse_subject(subject_prefix, enroll_id)
    csr_pem = create_csr(private_key, subject)

    auth = build_auth_header(enroll_id, enroll_secret)
    headers = {
        "x-api-key": f"{api_key}",
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/json"
    }

    body = {
        "certificate_request": csr_pem.decode("utf-8")
    }

    enroll_url = ca_url.rstrip("/") + "/proxy" + "/enroll" + "?RequestId=TICKET-APPROVED"
    print(f"🔐 Enrolling '{enroll_id}' at {enroll_url} with subject: {subject.rfc4514_string()}")

    response = requests.post(enroll_url, headers=headers, data=json.dumps(body), verify=False)

    if response.status_code not in (200, 201):
        print(f"❌ Enrollment failed: {response.status_code}")
        print(response.text)
        return

    result = response.json()["result"]
    def decode_if_base64(value):
        if value.strip().startswith("-----BEGIN"):
            return value
        return base64.b64decode(value).decode("utf-8")

    cert_pem = decode_if_base64(result["Cert"])
    ca_chain = decode_if_base64(result["ServerInfo"]["CAChain"])

    with open(f"{output_prefix}-key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))

    with open(f"{output_prefix}-cert.pem", "w") as f:
        f.write(cert_pem)

    with open(f"{output_prefix}-ca.pem", "w") as f:
        f.write(ca_chain)

    print("✅ Enrollment complete.")
    print(f"📄 Private key: {output_prefix}-key.pem")
    print(f"📄 Certificate: {output_prefix}-cert.pem")
    print(f"📄 CA chain:    {output_prefix}-ca.pem")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Enroll with Hyperledger Fabric CA")
    parser.add_argument("--url", required=True, help="Base URL of Fabric CA (e.g. http://fabric-ca-server:7054)")
    parser.add_argument("--id", required=True, help="Enrollment ID (used as CN)")
    parser.add_argument("--secret", required=True, help="Enrollment secret")
    parser.add_argument("--apikey", required=True, help="proxy api key")
    parser.add_argument("--output", required=True, help="Prefix for output files")
    parser.add_argument("--subject", required=True, help='Subject prefix string (e.g. "/C=US/ST=NC/O=Org/OU=Dept")')

    args = parser.parse_args()
    enroll(args.url, args.id, args.secret, args.output, args.subject, args.apikey)

