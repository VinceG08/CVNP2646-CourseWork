#!/usr/bin/env python3
# ip_validator.py
# Validates IPv4 addresses

def validate_ip(ip_address):
    """
    Validates if a string is a valid IPv4 address.

    Args:
        ip_address (str): The IP address to validate

    Returns:
        bool: True if valid, False otherwise
    """
    try:
        # Split the IP address by dots
        octets = ip_address.split('.')

        # Check if there are exactly 4 parts
        if len(octets) != 4:
            return False

        # Check each octet
        for octet in octets:
            # Convert to integer
            num = int(octet)

            # Check if in valid range (0-255)
            if num < 0 or num > 255:
                return False

        # If all checks pass, it's valid
        return True

    except ValueError:
        # If conversion to int fails, it's not valid
        return False


# Test cases
test_ips = [
    "192.168.1.1",       # Valid
    "10.0.0.1",          # Valid
    "256.1.1.1",         # Invalid (256 > 255)
    "192.168.1",         # Invalid (only 3 octets)
    "abc.def.ghi.jkl",   # Invalid (not numbers)
    "192.168.1.1.1"      # Invalid (5 octets)
]

print("IP Address Validator")
print("=" * 40)

for ip in test_ips:
    result = "✅ VALID" if validate_ip(ip) else "❌ INVALID"
    print(f"{ip:20} → {result}")


# Interactive mode
print("\n" + "="*40)
user_ip = input("\nEnter an IP adress to validate: ")
if validate_ip(user_ip):
    print(f"✅ {user_ip} is a VALID IPv4 address!")
else:
    print(f"❌ {user_ip} is NOT a valid IPv4 address.")