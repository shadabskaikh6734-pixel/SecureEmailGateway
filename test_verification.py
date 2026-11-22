import dkim
import base64

from pathlib import Path
from cryptography.hazmat.primitives import serialization


# Read signed email
with open("signed_email.eml", "rb") as file:
    email_data = file.read()


# Load private key
private_key = serialization.load_pem_private_key(
    Path("keys/mail_private.pem").read_bytes(),
    password=None
)


# Extract public key
public_key = private_key.public_key()

public_der = public_key.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

public_base64 = base64.b64encode(public_der).decode()


# Construct DKIM DNS record
dns_record = (
    f"v=DKIM1; k=rsa; p={public_base64}"
).encode()


# Local DNS lookup function
def local_dns_lookup(name, timeout=5):

    if isinstance(name, bytes):
        name = name.decode()

    name = name.rstrip(".").lower()

    if name == "mail._domainkey.example.com":
        return dns_record

    return None


# Verify DKIM signature
try:

    result = dkim.verify(
        email_data,
        dnsfunc=local_dns_lookup
    )

    if result:
        print("\nDKIM VERIFICATION: PASS")
        print("Signature is cryptographically valid.")

    else:
        print("\nDKIM VERIFICATION: FAIL")
        print("Signature is invalid.")

except Exception as error:

    print("\nVERIFICATION ERROR:")
    print(error)