import json
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from base64 import b64encode

# 1. Load private key from PEM
private_key_pem = b"""-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/PlByKY3Scozz4IM
gjCfeZ2W/Raf9Wg4hTHlm6ujjXShRANCAAQ0afOcZjOcYLisbFsZ2go9R6+9Wqqw
AJXiEllpfkyIDv+shef2EyAOsBWZiNEk2lMdDup7e2TcAb6Es+S7Dp0R
-----END PRIVATE KEY-----"""

private_key = serialization.load_pem_private_key(private_key_pem, password=None)

# 2. Create the registration payload
payload = {
    "id": "appUser6",
    "type": "client",
    "secret": "password",
    "affiliation": "org1.department1"
}
payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')  # no whitespace
print(payload_bytes)

# 3. Sign the payload
signature = private_key.sign(
    payload_bytes,
    ec.ECDSA(hashes.SHA256())
)

# 4. Print Base64-encoded signature
print(b64encode(signature).decode())

