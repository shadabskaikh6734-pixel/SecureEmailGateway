from email import policy
from email.parser import Parser


def parse_header(raw_email):

    try:

        message = Parser(
            policy=policy.default
        ).parsestr(raw_email)

        return {
            "from": str(message.get("From", "Unknown")),
            "to": str(message.get("To", "Unknown")),
            "subject": str(message.get("Subject", "Unknown")),
            "date": str(message.get("Date", "Unknown")),
            "message_id": str(
                message.get("Message-ID", "Unknown")
            ),
            "authentication_results": str(
                message.get("Authentication-Results", "Not available")
            )
        }

    except Exception as e:

        return {
            "error": str(e)
        }