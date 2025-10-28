import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# ============================================================
# 1️⃣ Simple Homomorphic Encryption (same as server)
# ============================================================

class HomomorphicEncryption:
    def __init__(self, key):
        self.key = key

    def encrypt(self, value):
        import random
        noise = random.randint(10, 50)
        return value + self.key + noise, noise

    def decrypt(self, enc_value, noise):
        return enc_value - self.key - noise

    def add_encrypted(self, enc_val1, enc_val2):
        return enc_val1 + enc_val2


# ============================================================
# 2️⃣ Prepare Transactions
# ============================================================

def prepare_transactions(he_key):
    sellers = {
        "Seller_A": [100, 250],
        "Seller_B": [150, 200, 50]
    }

    encrypted_data = {}
    for seller, txs in sellers.items():
        encrypted_data[seller] = []
        for amt in txs:
            enc_val, noise = he_key.encrypt(amt)
            encrypted_data[seller].append((enc_val, noise, amt))
    return encrypted_data


# ============================================================
# 3️⃣ Signature Verification (RSA + SHA-256)
# ============================================================

def verify_signature(summary, signature_hex, rsa_pub_pem):
    rsa_pub = RSA.import_key(rsa_pub_pem)
    signature = bytes.fromhex(signature_hex)
    summary_json = json.dumps(summary, indent=2)
    hash_obj = SHA256.new(summary_json.encode())

    try:
        pkcs1_15.new(rsa_pub).verify(hash_obj, signature)
        return True
    except (ValueError, TypeError):
        return False


# ============================================================
# 4️⃣ Client Socket Handling
# ============================================================

def main():
    host = "127.0.0.1"
    port = 5003

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        cli.connect((host, port))

        # Receive homomorphic key
        key_val = int(cli.recv(4096).decode())
        he_key = HomomorphicEncryption(key_val)
        cli.sendall(b"ACK")

        # Encrypt transactions
        encrypted_data = prepare_transactions(he_key)

        # Send to server
        cli.sendall(json.dumps(encrypted_data).encode())

        # Receive signed summary
        response = cli.recv(8192)
        resp_data = json.loads(response.decode())

        summary = resp_data["summary"]
        signature = resp_data["signature"]
        rsa_pub_pem = resp_data["rsa_pub"]

        # Verify signature
        verified = verify_signature(summary, signature, rsa_pub_pem)

        print("\n=== 💰 Transaction Summary ===")
        print(json.dumps(summary, indent=2))
        print(f"\n🔐 Signature Verification: {'✅ VALID' if verified else '❌ INVALID'}")


if __name__ == "__main__":
    main()
