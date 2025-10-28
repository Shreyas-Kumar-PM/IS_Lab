import socket
import json
from typing import Tuple, Dict, List
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import random
from math import gcd
from functools import reduce

# ========== PAILLIER ENCRYPTION IMPLEMENTATION ==========
def lcm(a, b): return a * b // gcd(a, b)

def modinv(a, m):
    def egcd(a, b):
        if b == 0: return (1, 0, a)
        x, y, g = egcd(b, a % b)
        return (y, x - (a // b) * y, g)
    x, y, g = egcd(a, m)
    if g != 1: raise ValueError("No modular inverse")
    return x % m

class PaillierPublicKey:
    def __init__(self, n, g):
        self.n = n
        self.g = g
        self.n2 = n * n

class PaillierPrivateKey:
    def __init__(self, lam, mu):
        self.lam = lam
        self.mu = mu

def paillier_keygen(bits=256):
    from Crypto.Util import number
    p = number.getPrime(bits // 2)
    q = number.getPrime(bits // 2)
    n = p * q
    g = n + 1
    lam = lcm(p - 1, q - 1)
    n2 = n * n
    def L(u): return (u - 1) // n
    mu = modinv(L(pow(g, lam, n2)), n)
    return PaillierPublicKey(n, g), PaillierPrivateKey(lam, mu)

def paillier_encrypt(pub, m):
    from Crypto.Random import random
    r = random.StrongRandom().randint(1, pub.n - 1)
    return (pow(pub.g, m, pub.n2) * pow(r, pub.n, pub.n2)) % pub.n2

def paillier_decrypt(pub, priv, c):
    def L(u): return (u - 1) // pub.n
    return (L(pow(c, priv.lam, pub.n2)) * priv.mu) % pub.n

def paillier_add(pub, c_list):
    result = 1
    for c in c_list:
        result = (result * c) % pub.n2
    return result

# ========================================================

def generate_rsa(bits: int = 2048) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    key = RSA.generate(bits)
    return key.publickey(), key


def main() -> None:
    host = "127.0.0.1"
    port = 5005

    # Generate keys
    pub_pail, priv_pail = paillier_keygen()
    pub_rsa, priv_rsa = generate_rsa(2048)
    rsa_pub_pem = pub_rsa.export_key()

    # Store transactions from sellers
    all_sellers: Dict[str, Dict] = {}

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind((host, port))
        srv.listen(5)
        print(f"[SERVER] Payment Gateway listening on {host}:{port}")

        for _ in range(2):  # Expecting two sellers
            conn, _ = srv.accept()
            with conn:
                # Step 1: Send Paillier + RSA public key info
                pub_data = {
                    "paillier_n": str(pub_pail.n),
                    "paillier_g": str(pub_pail.g),
                    "rsa_pub": rsa_pub_pem.decode()
                }
                data = json.dumps(pub_data).encode()
                conn.sendall(len(data).to_bytes(4, "big") + data)

                # Step 2: Receive seller transactions
                length = int.from_bytes(conn.recv(4), "big")
                payload = conn.recv(length)
                seller_data = json.loads(payload.decode())

                name = seller_data["seller_name"]
                tx_plain = seller_data["transactions_plain"]
                tx_encrypted = [int(x) for x in seller_data["transactions_encrypted"]]

                total_enc = paillier_add(pub_pail, tx_encrypted)
                total_dec = paillier_decrypt(pub_pail, priv_pail, total_enc)
                dec_individual = [paillier_decrypt(pub_pail, priv_pail, c) for c in tx_encrypted]

                all_sellers[name] = {
                    "Seller": name,
                    "Individual Transactions": tx_plain,
                    "Encrypted Transactions": tx_encrypted,
                    "Decrypted Transactions": dec_individual,
                    "Total Encrypted": total_enc,
                    "Total Decrypted": total_dec
                }

                conn.sendall(len(b"ACK").to_bytes(4, "big") + b"ACK")

        # Build summary after all sellers sent data
        summary = json.dumps(all_sellers, indent=2).encode()
        h = SHA256.new(summary)
        signature = pkcs1_15.new(priv_rsa).sign(h)

        print("\n===== TRANSACTION SUMMARY =====")
        print(summary.decode())
        print("===============================")
        print(f"[SERVER] SHA256 hash: {h.hexdigest()}")
        print(f"[SERVER] Digital Signature (hex): {signature.hex()[:64]}...")

        # Broadcast summary + signature to sellers (demo)
        print("[SERVER] Summary signed and stored as proof.")


if __name__ == "__main__":
    main()
