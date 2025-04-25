from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509 import load_pem_x509_certificate
from cryptography.exceptions import InvalidSignature
from base64 import b64decode
import base64
import hashlib
import json


with open("cert.pem", "rb") as f:
    rd_cert_pem = f.read()


# ----- BEGIN: Sample Inputs -----

cert_pem = b"""-----BEGIN CERTIFICATE-----
MIICPDCCAeKgAwIBAgIUWqAEhCyVRVBKAJwGm3Bs/xa7VJ8wCgYIKoZIzj0EAwIw
aDELMAkGA1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQK
EwtIeXBlcmxlZGdlcjEPMA0GA1UECxMGRmFicmljMRkwFwYDVQQDExBmYWJyaWMt
Y2Etc2VydmVyMB4XDTI1MDQwNDIxMDQwMFoXDTI2MDQwNDIxMzYwMFowXTELMAkG
A1UEBhMCVVMxFzAVBgNVBAgTDk5vcnRoIENhcm9saW5hMRQwEgYDVQQKEwtIeXBl
cmxlZGdlcjEPMA0GA1UECxMGY2xpZW50MQ4wDAYDVQQDEwVhZG1pbjBZMBMGByqG
SM49AgEGCCqGSM49AwEHA0IABDRp85xmM5xguKxsWxnaCj1Hr71aqrAAleISWWl+
TIgO/6yF5/YTIA6wFZmI0STaUx0O6nt7ZNwBvoSz5LsOnRGjdTBzMA4GA1UdDwEB
/wQEAwIHgDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTcVKqc2CMJuJ79Y2JbFk3v
j/jp4DAfBgNVHSMEGDAWgBTiGdDHC7Y7rLFPqdsIFF2LBknq3DATBgNVHREEDDAK
gghMLVNBbGxhbjAKBggqhkjOPQQDAgNIADBFAiEA7cLyUAY1oAUcEdYWg7r310lY
L80+XlH6OgalZ0cFiOICIHPEQvnu+gThkOR0hiRYOw4rzv50Vwp7l3InYKGxo7pN
-----END CERTIFICATE-----"""

#signature_b64 = "MEQCIEoc0eokpHVUw3v6c128Er37Oql49+lmlkFN6yElFbizAiA0K+mSvUPTdnhFx7Z2oqA9XvnS/87kL3/hqEwksHZ+xg=="
#works for appUser6
#signature_b64 = "MEQCIDzAq/sLkn5pC/I39k4KviyxAX2HoTAdSwYZuFyv/kYdAiAa1VeGn9JTDxAYN/epFA3nropyksjI4f87okHg+LkQWw=="

#Test for appUser8
signature_b64 = "MEUCIGLDBf+u5yatmZDqqtnIv56beHkoNt3QgeXjtMqqezyKAiEAvWZUDBcSwTLQBYMo+HK+v2zZ9KTLTl31k7zRrr1B1M0="
signature_bytes = b64decode(signature_b64)

payload = {
    "id": "appUser6",
    "type": "client",
    "secret": "password",
    "affiliation": "org1.department1"
}
#payload_bytes = json.dumps(payload, separators=(',', ':')).encode('utf-8')
#works for appUser6
#payload_bytes = b'{"id":"appUser6","type":"client","secret":"password","affiliation":"org1.department1"}'
payload_bytes = b'{"id":"appUser8","type":"client","secret":"password","affiliation":"org1.department1"}'
print(payload_bytes)
print(payload_bytes.decode())
print(payload_bytes.hex())
#signing_string = b'POST' + b'http://fabric-ca-server:7054/register' + payload_bytes
signing_string = b'POST' + b'/register' + payload_bytes
print(signing_string.decode())

digest = hashlib.sha256(signing_string).digest()

# ----- END: Sample Inputs -----

# 1. Load the certificate and extract public key
cert = load_pem_x509_certificate(cert_pem)
#raw_cert = cert.public_bytes(serialization.Encoding.DER)
#raw_cert = cert_pem.strip()
#raw_cert = cert_pem
raw_cert = rd_cert_pem
public_key = cert.public_key()

method = "POST"
uri = "/register"
body = payload_bytes
b64uri = base64.b64encode(uri.encode('utf-8')).decode('ascii')
b64body = base64.b64encode(body).decode('ascii')
b64cert = base64.b64encode(raw_cert).decode('ascii')

new_signing_string = f"{method}.{b64uri}.{b64body}.{b64cert}".encode('utf-8')
print(new_signing_string)

newdigest = hashlib.sha256(new_signing_string).digest()

# 2. Verify the signature
try:
    public_key.verify(
        signature_bytes,
        payload_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    print("✅ Signature is valid.")
except InvalidSignature:
    print("❌ Signature is INVALID.")

try:
    public_key.verify(
        signature_bytes,
        digest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    print("✅ Signature is valid.")
except InvalidSignature:
    print("❌ Signature is INVALID.")

try:
    public_key.verify(
        signature_bytes,
        newdigest,
        ec.ECDSA(utils.Prehashed(hashes.SHA256()))
    )
    print("✅ Signature is valid.")
except InvalidSignature:
    print("❌ Signature is INVALID.")
