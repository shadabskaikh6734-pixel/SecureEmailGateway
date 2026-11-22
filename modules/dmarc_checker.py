import dns.resolver
from publicsuffix2 import get_sld


def aligned(domain1, domain2):

    if not domain1 or not domain2:
        return False

    return (
        get_sld(domain1.lower().strip(".")) ==
        get_sld(domain2.lower().strip("."))
    )


def check_dmarc(domain, spf_result, dkim_result,
                spf_domain=None, dkim_domain=None):

    try:

        records = dns.resolver.resolve(
            f"_dmarc.{domain}",
            "TXT"
        )

        dmarc_record = None

        for record in records:

            value = record.to_text().strip('"')

            if value.startswith("v=DMARC1"):
                dmarc_record = value
                break

        if not dmarc_record:

            return {
                "status": "FAIL",
                "message": "DMARC record not found"
            }

        policy = "none"

        for item in dmarc_record.split(";"):

            item = item.strip()

            if item.startswith("p="):
                policy = item.split("=", 1)[1]

        spf_aligned = (
            spf_result == "PASS"
            and aligned(spf_domain, domain)
        )

        dkim_aligned = (
            dkim_result == "PASS"
            and aligned(dkim_domain, domain)
        )

        dmarc_pass = spf_aligned or dkim_aligned

        return {
            "status": "PASS" if dmarc_pass else "FAIL",
            "policy": policy,
            "record": dmarc_record,
            "spf_alignment": spf_aligned,
            "dkim_alignment": dkim_aligned,
            "message": (
                "DMARC authentication passed"
                if dmarc_pass
                else "DMARC authentication failed"
            )
        }

    except Exception as e:

        return {
            "status": "ERROR",
            "message": str(e)
        }