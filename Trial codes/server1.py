import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import random


# ============================================================
# 1️⃣ Simple Homomorphic Encryption (Conceptual)
# ============================================================

class HomomorphicEncryption:
    """
    Simulated additive homomorphic encryption.
    Enc(a) + Enc(b) = Enc(a + b)
    (For demonstration only — not secure, but conceptually correct.)
    """
    def __init__(self, key):
        self.key = key

    def encrypt(self, value):
        # simple encryption: value + random noise + key
        noise = random.randint(10, 50)
        return value + self.key + noise, noise

    def decrypt(self, enc_value, noise):
        return enc_value - self.key - noise

    def add_encrypted(self, enc_val1, enc_val2):
        # homomorphic addition property
        return enc_val1 + enc_val2


# ============================================================
# 2️⃣ RSA Key Generation
# ============================================================

def generate_rsa_keys():
    key = RSA.generate(2048)
    return key.publickey(), key


# ============================================================
# 3️⃣ Transaction Computation
# ============================================================

def compute_totals(transactions, he_key):
    """
    Combine encrypted transactions and decrypt totals per seller.
    """
    summary = []

    for seller, tx_list in transactions.items():
        total_enc = 0
        total_dec = 0
        for enc_val, noise, plain in tx_list:
            total_enc = he_key.add_encrypted(total_enc, enc_val)
            total_dec += plain
        # decrypt combined total
        dec_total = he_key.decrypt(total_enc, sum([n for _, n, _ in tx_list]))
        summary.append({
            "seller": seller,
            "total_decrypted_amount": dec_total,
            "total_plain_sum": total_dec,
        })
    return summary


# ============================================================
# 4️⃣ Digital Signature using SHA-256 + RSA
# ============================================================

def sign_summary(summary, rsa_priv):
    summary_json = json.dumps(summary, indent=2)
    hash_obj = SHA256.new(summary_json.encode())
    signature = pkcs1_15.new(rsa_priv).sign(hash_obj)
    return signature.hex(), summary_json


# ============================================================
# 5️⃣ Server Socket Handling
# ============================================================

def main():
    host = "127.0.0.1"
    port = 5003

    # Generate keys
    rsa_pub, rsa_priv = generate_rsa_keys()
    he_key = HomomorphicEncryption(key=100)

    print("💳 Payment Gateway Server Running...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind((host, port))
        srv.listen(1)
        conn, addr = srv.accept()
        with conn:
            print(f"✅ Connected with {addr}")

            # Send public key info (homomorphic key)
            conn.sendall(str(he_key.key).encode())
            conn.recv(1024)  # ACK

            # Receive seller transactions
            data = conn.recv(8192)
            transactions = json.loads(data.decode())

            # Compute totals
            summary = compute_totals(transactions, he_key)

            # Sign summary
            signature_hex, summary_json = sign_summary(summary, rsa_priv)

            # Send summary, signature, and RSA public key
            payload = json.dumps({
                "summary": summary,
                "signature": signature_hex,
                "rsa_pub": rsa_pub.export_key().decode()
            })
            conn.sendall(payload.encode())

            print("\n🧾 Transaction Summary Sent:")
            print(summary_json)


if __name__ == "__main__":
    main()

