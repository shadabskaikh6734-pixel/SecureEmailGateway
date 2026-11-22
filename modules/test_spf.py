from modules.spf_checker import check_spf

# Test email information
ip = "54.240.113.47"

sender = (
    "010101a1ae5b6ee3-89c22a3d-7c99-4bab-9be8-c15f3636312-000000"
    "@mail-us2.e-mail.hoyoverse.com"
)

helo = "a113-47.smtp-out.us-west-2.amazonses.com"

domain = "e-mail.hoyoverse.com"

# Perform SPF verification
result = check_spf(
    domain,
    ip,
    sender,
    helo
)

print("\n========== SPF VERIFICATION ==========")

print("Status:", result["status"])
print("Domain:", result["domain"])
print("Sending IP:", result["ip"])
print("Message:", result["message"])

print("======================================")
