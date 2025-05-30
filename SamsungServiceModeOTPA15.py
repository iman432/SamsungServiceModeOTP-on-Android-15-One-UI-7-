import hmac
import hashlib
import time

SECRET_HEX = "120395F099840593405B03838449A72933484040A3034750C0403938290A293B"
INTERVAL = 300  # 5 minutes
CODE_DIGITS = 6

def hex_str_to_bytes(hex_str):
    return bytes.fromhex(hex_str)

def generate_totp_nonce(counter_hex, nonce):
    # Build input string
    if nonce.isnumeric() and len(nonce) == 6:
        input_str = (nonce + counter_hex).rjust(22, '0')
    else:
        print("wrong nonce error")
        input_str = counter_hex.rjust(16, '0')

    msg_bytes = hex_str_to_bytes(input_str)
    key_bytes = hex_str_to_bytes(SECRET_HEX)

    hmac_hash = hmac.new(key_bytes, msg_bytes, hashlib.sha256).digest()
    offset = hmac_hash[-1] & 0x0F

    code = (
        ((hmac_hash[offset] & 0x7F) << 24) |
        ((hmac_hash[offset + 1] & 0xFF) << 16) |
        ((hmac_hash[offset + 2] & 0xFF) << 8) |
        (hmac_hash[offset + 3] & 0xFF)
    ) % (10 ** CODE_DIGITS)

    return str(code).zfill(CODE_DIGITS)

def gen_otp_6digit_nonce(input_str):
    nonce = input_str[2:] if input_str else ""
    current_time = int(time.time())
    print(f"The current UTC time is {current_time}")
    counter = int(current_time / INTERVAL)
    counter_hex = hex(counter)[2:].upper().rjust(16, '0')

    otp = generate_totp_nonce(counter_hex, nonce)
    print(f"final OTP: {otp}")
    return otp

# Example usage
input_str = "01507803"  # your input
gen_otp_6digit_nonce(input_str)
