from modules.email_signer import sign_email

email = """From: sender@example.com
To: receiver@example.net
Subject: DKIM Authentication Test
Date: Fri, 06 Nov 2026 10:00:00 +0000
Message-ID: <test123@example.com>

This is a test email for DKIM authentication.
"""

result = sign_email(
    raw_email=email,
    domain="example.com",
    selector="mail",
    private_key_path="keys/mail_private.pem"
)

print("\nDKIM EMAIL SIGNING RESULT")
print("Status:", result["status"])
print("Message:", result["message"])

if result["status"] == "SUCCESS":

    with open("signed_email.eml", "wb") as file:
        file.write(result["signed_email"])

    print("\nSigned email saved successfully.")