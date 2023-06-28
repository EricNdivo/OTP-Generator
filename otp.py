import hmac
import hashlib
import time


def generate_otp(secret_key, interval=30, digits=6, count=1):
    otps = []
    for _ in range(count):
        timestamp = int(time.time()) // interval  # Calculate the timestamp based on the interval
        message = bytes(str(timestamp), 'utf-8')
        key = bytes.fromhex(secret_key)
        hmac_digest = hmac.new(key, message, hashlib.sha1).digest()

        offset = hmac_digest[-1] & 0x0F
        truncated_hash = hmac_digest[offset : offset + 4]

        # Calculate the OTP value by masking the most significant bit
        otp_value = int.from_bytes(truncated_hash, 'big') & 0x7FFFFFFF
        otp = str(otp_value % 10**digits).zfill(digits)  # Convert to specified number of digits

        otps.append(otp)

        # Wait for the next interval
        time.sleep(interval)

    return otps


# Example usage
secret_key = '3132333435363738393031323334353637383930'  # Example secret key in hexadecimal format
otp_count = 5  # Number of OTPs to generate

generated_otps = generate_otp(secret_key, count=otp_count)
print("Generated OTPs:", generated_otps)
