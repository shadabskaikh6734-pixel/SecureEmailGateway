import dkim


def check_dkim(raw_email):

    try:

        email_data = raw_email.encode("utf-8")

        if not b"DKIM-Signature:" in email_data:
            return {
                "status": "FAIL",
                "message": "DKIM signature not found"
            }

        result = dkim.verify(email_data)

        if result:

            return {
                "status": "PASS",
                "message": "DKIM signature is valid"
            }

        return {
            "status": "FAIL",
            "message": "DKIM signature verification failed"
        }

    except Exception as e:

        return {
            "status": "ERROR",
            "message": str(e)
        }