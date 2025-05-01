#!/usr/bin/env python3
# filepath: /home/sallan/src/github.com/fabric-ca-proxy/client/proxy_client.py
import os
import json
import base64
import hashlib
import requests
import argparse
import sys
from urllib.parse import urlparse

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


# === Shared Functions ===

def normalize_url(ca_url, path_suffix="", request_id=None):
    """
    Normalize a URL to ensure proper format with optional path suffix and request ID.
    """
    url_parts = list(urlparse(ca_url))
    if not url_parts[0]:  # No scheme
        url_parts[0] = "https"
    
    base_url = f"{url_parts[0]}://{url_parts[1]}"
    path = url_parts[2].rstrip('/')
    
    # Ensure path includes /proxy path_suffix
    if not path.endswith(path_suffix) and not f"/proxy{path_suffix}" in path:
        if not path.endswith("/proxy"):
            path = f"{path}/proxy"
        path = f"{path}{path_suffix}"
    
    full_url = f"{base_url}{path}"
    
    # Add request ID as query parameter if provided
    if request_id:
        full_url += f"?RequestId={request_id}"
    
    return full_url

# === Enrollment Functions ===

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

def enroll(ca_url, enroll_id, enroll_secret, output_prefix, subject_prefix, api_key, request_id="TICKET-APPROVED", verify=True):
    """
    Enroll a client with Fabric CA Server using ID and secret.
    """
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

    enroll_url = normalize_url(ca_url, "/enroll", request_id)
    print(f"🔐 Enrolling '{enroll_id}' at {enroll_url} with subject: {subject.rfc4514_string()}")

    response = requests.post(enroll_url, headers=headers, data=json.dumps(body), verify=verify)

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

# === Registration Functions ===

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

def register_client(ca_url, cert_path, key_path, json_file, api_key=None, 
                   request_id="TICKET-APPROVED", verify=True, output_prefix=None):
    """
    Register a client with Fabric CA Server using certificate-based authentication.
    """
    method = "POST"
    uri = "/register"
    payload = load_payload(json_file)
    body_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')

    # Load certificate and private key
    try:
        cert_pem, private_key = load_key_and_cert(cert_path, key_path)
    except Exception as e:
        print(f"❌ Failed to load certificate or key: {e}")
        sys.exit(1)
    
    # Create auth token
    auth_token = create_auth_token(cert_pem, private_key, method, uri, body_bytes)

    # Set up headers
    headers = {
        "Authorization": auth_token,
        "Content-Type": "application/json",
        "User-Agent": "Go-http-client/1.1"
    }
    
    # Add API key if provided
    if api_key:
        headers["x-api-key"] = api_key
    
    register_url = normalize_url(ca_url, "/register", request_id)
    
    print(f"📡 Sending registration request to: {register_url}")
    print(f"🔐 Registering client with payload: {json.dumps(payload, indent=2)}")

    # Make the request
    try:
        response = requests.post(
            register_url, 
            headers=headers, 
            data=body_bytes, 
            verify=verify
        )
    except requests.exceptions.RequestException as e:
        print(f"❌ Request failed: {e}")
        return

    # Print response
    print(f"\n🌐 Response: {response.status_code}")
    print(response.text)
    
    # Save response to file if output prefix provided
    if output_prefix and response.status_code in (200, 201):
        try:
            resp_data = response.json()
            with open(f"{output_prefix}-response.json", "w") as f:
                json.dump(resp_data, f, indent=2)
            print(f"\n✅ Response saved to {output_prefix}-response.json")
        except Exception as e:
            print(f"⚠️  Could not save response to file: {e}")

# === Main Function and CLI ===

def main():
    parser = argparse.ArgumentParser(description="Hyperledger Fabric CA Proxy Client")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Common parameters
    common_parser = argparse.ArgumentParser(add_help=False)
    common_parser.add_argument("--url", required=True, 
                      help="Base URL of Fabric CA (e.g. http://fabric-ca-server:7054)")
    common_parser.add_argument("--apikey", default="changeme-key1",
                      help="API key for the proxy (default: changeme-key1)")
    common_parser.add_argument("--requestid", default="TICKET-APPROVED",
                      help="Request ID for tracking/approval (default: TICKET-APPROVED)")
    common_parser.add_argument("--insecure", action="store_true", default=True,
                      help="Skip SSL certificate verification (default: True)")
    common_parser.add_argument("--output", 
                      help="Prefix for output files")
    
    # Register command
    register_parser = subparsers.add_parser("register", parents=[common_parser], 
                                          help="Register a client with Fabric CA")
    register_parser.add_argument("--cert", required=True, 
                              help="Path to the admin/registrar certificate file")
    register_parser.add_argument("--key", required=True, 
                              help="Path to the admin/registrar private key file")
    register_parser.add_argument("--json", required=True, 
                              help="Path to JSON file containing registration payload")
    
    # Enroll command
    enroll_parser = subparsers.add_parser("enroll", parents=[common_parser], 
                                        help="Enroll with Fabric CA")
    enroll_parser.add_argument("--id", required=True, 
                            help="Enrollment ID (used as CN)")
    enroll_parser.add_argument("--secret", required=True, 
                            help="Enrollment secret")
    enroll_parser.add_argument("--subject", required=True, 
                            help='Subject prefix string (e.g. "/C=US/ST=NC/O=Org/OU=Dept")')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    if args.command == "register":
        register_client(
            ca_url=args.url,
            cert_path=args.cert,
            key_path=args.key,
            json_file=args.json,
            api_key=args.apikey,
            request_id=args.requestid,
            verify=not args.insecure,
            output_prefix=args.output
        )
    elif args.command == "enroll":
        if not args.output:
            print("❌ --output is required for enroll command")
            sys.exit(1)
        
        enroll(
            ca_url=args.url,
            enroll_id=args.id,
            enroll_secret=args.secret,
            output_prefix=args.output,
            subject_prefix=args.subject,
            api_key=args.apikey,
            request_id=args.requestid,
            verify=not args.insecure
        )

if __name__ == "__main__":
    main()
