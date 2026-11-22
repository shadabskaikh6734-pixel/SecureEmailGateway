import os
import base64

from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


def generate_dkim_keys(domain, selector="mail"):

    # Validate domain
    if not domain or "." not in domain:
        raise ValueError("Enter a valid domain name")

    # Generate 2048-bit RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    # Generate public key
    public_key = private_key.public_key()

    # Convert private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Convert public key to DER
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Base64 encode public key
    public_base64 = base64.b64encode(
        public_der
    ).decode("utf-8")

    # Create keys directory
    keys_dir = Path("keys")
    keys_dir.mkdir(exist_ok=True)

    # Save private key
    private_path = keys_dir / f"{selector}_private.pem"

    private_path.write_bytes(private_pem)

    # Generate DNS record
    dns_record = (
        f"v=DKIM1; k=rsa; p={public_base64}"
    )

    dns_name = f"{selector}._domainkey.{domain}"

    return {
        "private_key": str(private_path),
        "dns_name": dns_name,
        "dns_record": dns_record,
        "selector": selector
    }