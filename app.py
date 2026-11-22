from flask import Flask, render_template, request

from modules.spf_checker import check_spf
from modules.dkim_checker import check_dkim
from modules.dmarc_checker import check_dmarc
from modules.header_parser import parse_header

import re

app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():

    results = None

    if request.method == "POST":

        raw_email = request.form.get("raw_email", "")
        ip = request.form.get("ip", "").strip()
        sender = request.form.get("sender", "").strip()
        helo = request.form.get("helo", "").strip()

        try:

            headers = parse_header(raw_email)

            if "error" in headers:
                raise ValueError(headers["error"])

            from_address = headers["from"]

            match = re.search(
                r'[\w.+-]+@([\w.-]+\.[A-Za-z]{2,})',
                from_address
            )

            if not match:
                raise ValueError("Invalid From email address")

            domain = match.group(1)

            if not ip or not sender:
                raise ValueError("IP and sender are required")

            spf_domain = sender.split("@")[-1]

            if not helo:
                helo = spf_domain

            spf_result = check_spf(
                spf_domain,
                ip,
                sender,
                helo
            )

            dkim_result = check_dkim(raw_email)

            # Extract the DKIM signing domain.
            dkim_domain_match = re.search(
                r'(?im)^DKIM-Signature:.*?\bd=([^;\s]+)',
                raw_email
            )

            dkim_domain = (
                dkim_domain_match.group(1).strip()
                if dkim_domain_match else None
            )

            spf_domain = sender.split("@")[-1]

            dmarc_result = check_dmarc(
                domain,
                spf_result["status"],
                dkim_result["status"],
                spf_domain,
                dkim_domain
            )

            results = {
                "headers": headers,
                "spf": spf_result,
                "dkim": dkim_result,
                "dmarc": dmarc_result
            }

            if dmarc_result["status"] == "PASS":
                results["overall"] = "SECURE"
            else:
                results["overall"] = "SUSPICIOUS"

        except Exception as e:

            results = {
                "error": str(e)
            }

    return render_template(
        "index.html",
        results=results
    )


if __name__ == "__main__":

    app.run(
        debug=False
    )