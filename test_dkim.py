from modules.dkim_generator import generate_dkim_keys

result = generate_dkim_keys(
    domain="example.com",
    selector="mail"
)

print("\nDKIM KEY GENERATION SUCCESSFUL")

print("\nPrivate Key:")
print(result["private_key"])

print("\nDNS Record Name:")
print(result["dns_name"])

print("\nDNS TXT Record:")
print(result["dns_record"])