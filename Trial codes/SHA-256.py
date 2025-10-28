# ==============================
# SHA-256 + RSA Signing & Verification
# ==============================

from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import json


def sign_summary_sha256(summary, rsa_priv):
    """
    Hash the transaction summary using SHA-256 and sign it using RSA private key.
    Returns the hexadecimal signature and summary JSON string.
    """
    summary_json = json.dumps(summary, indent=2)
    hash_obj = SHA256.new(summary_json.encode())
    signature = pkcs1_15.new(rsa_priv).sign(hash_obj)
    return signature.hex(), summary_json


def verify_signature_sha256(summary, signature_hex, rsa_pub_pem):
    """
    Verify the SHA-256 + RSA signature.
    Returns True if valid, False otherwise.
    """
    rsa_pub = RSA.import_key(rsa_pub_pem)
    signature = bytes.fromhex(signature_hex)
    summary_json = json.dumps(summary, indent=2)
    hash_obj = SHA256.new(summary_json.encode())

    try:
        pkcs1_15.new(rsa_pub).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False
