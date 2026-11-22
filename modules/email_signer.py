import dkim
from pathlib import Path


def sign_email(raw_email, domain, selector, private_key_path):

    try:
        # Load private key
        private_key = Path(private_key_path).read_bytes()

        # Convert email into bytes
        if isinstance(raw_email, str):
            raw_email = raw_email.encode("utf-8")

        # Headers to include in DKIM signature
        headers = [
            b"from",
            b"to",
            b"subject",
            b"date",
            b"message-id"
        ]

        # Generate DKIM signature
        signature = dkim.sign(
            message=raw_email,
            selector=selector.encode(),
            domain=domain.encode(),
            privkey=private_key,
            include_headers=headers,
            canonicalize=(b"relaxed", b"relaxed")
        )

        # Add signature to email
        signed_email = signature + raw_email

        return {
            "status": "SUCCESS",
            "message": "Email signed successfully",
            "signed_email": signed_email
        }

    except Exception as e:

        return {
            "status": "FAILED",
            "message": str(e)
        }