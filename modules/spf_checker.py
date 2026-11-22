import spf
import ipaddress


def check_spf(domain, ip, sender, helo):

    try:
        # Validate sending IP
        ipaddress.ip_address(ip)

        # Validate sender
        if "@" not in sender:
            raise ValueError("Invalid sender email")

        # Extract envelope sender domain
        sender_domain = sender.split("@")[-1]

        # Perform SPF DNS verification
        result, explanation= spf.check2(
            i=ip,
            s=sender,
            h=helo
        )

        return {
            "status": result.upper(),
            "domain": sender_domain,
            "ip": ip,
            "message": explanation,
            
        }

    except Exception as error:

        return {
            "status": "ERROR",
            "domain": domain,
            "ip": ip,
            "message": str(error)
        }