import socket
import json
import hashlib
import random


# ============================================================
# 1️⃣ Simple Homomorphic Encryption (Conceptual)
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
# 2️⃣ Rabin Key Generation and Signature Utilities
# ============================================================

def generate_rabin_keys(bits=512):
    """Generate Rabin public (n) and private (p, q) keys."""
    from sympy import randprime

    # ensure primes ≡ 3 mod 4
    def gen_prime():
        while True:
            p = randprime(2**(bits//2 - 1), 2**(bits//2))
            if p % 4 == 3:
                return p

    p = gen_prime()
    q = gen_prime()
    n = p * q
    return n, p, q


def rabin_sign(message_hash: int, p: int, q: int, n: int) -> int:
    """Compute Rabin signature using modular square roots and CRT."""
    # Compute square roots modulo p and q
    mp = pow(message_hash, (p + 1) // 4, p)
    mq = pow(message_hash, (q + 1) // 4, q)

    # Chinese Remainder Theorem to combine results
    yp = pow(p, -1, q)
    yq = pow(q, -1, p)
    signature = (mp * q * yq + mq * p * yp) % n
    return signature


def rabin_verify(message_hash: int, signature: int, n: int) -> bool:
    """Verify Rabin signature."""
    return pow(signature, 2, n) == (message_hash % n)


# ============================================================
# 3️⃣ Transaction Processing
# ============================================================

def compute_totals(transactions, he_key):
    summary = []
    for seller, tx_list in transactions.items():
        total_enc = 0
        total_plain = 0
        for enc_val, noise, plain in tx_list:
            total_enc = he_key.add_encrypted(total_enc, enc_val)
            total_plain += plain
        dec_total = he_key.decrypt(total_enc, sum([n for _, n, _ in tx_list]))
        summary.append({
            "seller": seller,
            "total_plain_sum": total_plain,
            "total_decrypted_amount": dec_total
        })
    return summary


# ============================================================
# 4️⃣ Server Main
# ============================================================

def main():
    host = "127.0.0.1"
    port = 5003

    # Generate keys
    he_key = HomomorphicEncryption(key=100)
    n, p, q = generate_rabin_keys()

    print("💳 Payment Gateway Server (RABIN) Running...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind((host, port))
        srv.listen(1)
        conn, addr = srv.accept()
        with conn:
            print(f"✅ Connected with {addr}")

            # Send public key (n)
            conn.sendall(str(n).encode())
            conn.recv(1024)

            # Receive encrypted transactions
            data = conn.recv(8192)
            transactions = json.loads(data.decode())

            # Compute totals
            summary = compute_totals(transactions, he_key)

            # Sign summary (hash with SHA-256)
            summary_json = json.dumps(summary, indent=2)
            h = int.from_bytes(hashlib.sha256(summary_json.encode()).digest(), "big")
            signature = rabin_sign(h, p, q, n)

            # Send back signature and summary
            payload = json.dumps({
                "summary": summary,
                "signature": str(signature),
                "rabin_pub": str(n)
            })
            conn.sendall(payload.encode())

            print("\n🧾 Transaction Summary Sent:")
            print(summary_json)


if __name__ == "__main__":
    main()
