import os
import json
import base64
import hashlib
import requests
import argparse
import sys
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


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

def register_client(ca_url, cert_path, key_path, json_file, api_key=None, 
                   request_id="TICKET-APPROVED", verify=True, output_prefix=None):
    """
    Register a client with Fabric CA Server using certificate-based authentication.
    
    Args:
        ca_url (str): The URL of the Fabric CA server
        cert_path (str): Path to the admin/registrar certificate
        key_path (str): Path to the admin/registrar private key
        json_file (str): Path to JSON file containing registration payload
        api_key (str): API key for the proxy
        request_id (str): Request ID for tracking/approval
        verify (bool): Whether to verify SSL certificates
        output_prefix (str): Optional prefix for saving response to file
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
    
    # Normalize URL
    url_parts = list(urlparse(ca_url))
    if not url_parts[0]:  # No scheme
        url_parts[0] = "https"
    
    base_url = f"{url_parts[0]}://{url_parts[1]}"
    path = url_parts[2].rstrip('/')
    
    # Ensure path includes /proxy/register
    if not path.endswith("/register") and not "/proxy/register" in path:
        if not path.endswith("/proxy"):
            path = f"{path}/proxy"
        path = f"{path}/register"
    
    register_url = f"{base_url}{path}"
    
    # Add request ID as query parameter if provided
    if request_id:
        register_url += f"?RequestId={request_id}"
    
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

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Register a client with Hyperledger Fabric CA")
    
    # Required arguments
    parser.add_argument("--url", required=True, 
                      help="Base URL of Fabric CA (e.g. http://fabric-ca-server:7054)")
    parser.add_argument("--cert", required=True, 
                      help="Path to the admin/registrar certificate file")
    parser.add_argument("--key", required=True, 
                      help="Path to the admin/registrar private key file")
    parser.add_argument("--json", required=True, 
                      help="Path to JSON file containing registration payload")
    
    # Optional arguments
    parser.add_argument("--apikey", default="changeme-key1",
                      help="API key for the proxy (default: changeme-key1)")
    parser.add_argument("--requestid", default="TICKET-APPROVED",
                      help="Request ID for tracking/approval (default: TICKET-APPROVED)")
    parser.add_argument("--output", 
                      help="Save response to file with given prefix")
    
    # Security option
    parser.add_argument("--insecure", action="store_true", default=True,
                      help="Skip SSL certificate verification (default: True)")

    args = parser.parse_args()
    
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

