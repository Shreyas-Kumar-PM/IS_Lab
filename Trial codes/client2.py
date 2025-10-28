import socket
import json
import hashlib
import random


# ============================================================
# 1️⃣ Simple Homomorphic Encryption (same as server)
# ============================================================

class HomomorphicEncryption:
    def __init__(self, key):
        self.key = key

    def encrypt(self, value):
        noise = random.randint(10, 50)
        return value + self.key + noise, noise

    def decrypt(self, enc_value, noise):
        return enc_value - self.key - noise

    def add_encrypted(self, enc1, enc2):
        return enc1 + enc2


# ============================================================
# 2️⃣ Rabin Signature Verification
# ============================================================

def rabin_verify(message_hash: int, signature: int, n: int) -> bool:
    """Verify Rabin signature."""
    return pow(signature, 2, n) == (message_hash % n)


# ============================================================
# 3️⃣ Prepare Seller Transactions
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
# 4️⃣ Client Main
# ============================================================

def main():
    host = "127.0.0.1"
    port = 5003

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        cli.connect((host, port))

        # Receive Rabin public key (n)
        n_val = int(cli.recv(4096).decode())
        he_key = HomomorphicEncryption(key=100)
        cli.sendall(b"ACK")

        # Encrypt transactions and send
        encrypted_data = prepare_transactions(he_key)
        cli.sendall(json.dumps(encrypted_data).encode())

        # Receive summary and signature
        response = cli.recv(8192)
        resp_data = json.loads(response.decode())

        summary = resp_data["summary"]
        signature = int(resp_data["signature"])
        n = int(resp_data["rabin_pub"])

        # Verify Rabin signature
        summary_json = json.dumps(summary, indent=2)
        h = int.from_bytes(hashlib.sha256(summary_json.encode()).digest(), "big")
        verified = rabin_verify(h, signature, n)

        print("\n=== 💰 Transaction Summary ===")
        print(summary_json)
        print(f"\n🔐 Rabin Signature Verification: {'✅ VALID' if verified else '❌ INVALID'}")


if __name__ == "__main__":
    main()
