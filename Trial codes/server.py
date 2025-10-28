import socket
import json
from typing import Tuple
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from phe import paillier  # pip install phe


# ============================================================
# 1️⃣ Key Generation (RSA + Paillier)
# ============================================================

def generate_rsa_keys(bits: int = 2048) -> Tuple[RSA.RsaKey, RSA.RsaKey]:
    """Generate RSA public and private key pair for digital signing."""
    key = RSA.generate(bits)
    return key.publickey(), key


def generate_paillier_keys():
    """Generate Paillier public and private key pair for encryption."""
    pub, priv = paillier.generate_paillier_keypair()
    return pub, priv


# ============================================================
# 2️⃣ Transaction Processing and Decryption
# ============================================================

def compute_totals(paillier_pub, paillier_priv, transactions):
    """
    Perform homomorphic addition of encrypted transactions,
    then decrypt totals per seller.
    """
    summary = []

    for seller, tx_list in transactions.items():
        total_enc = None
        total_plain = 0

        for enc_val, plain in tx_list:
            enc_num = paillier.EncryptedNumber(paillier_pub, enc_val)
            total_enc = enc_num if total_enc is None else total_enc + enc_num
            total_plain += plain

        decrypted_total = paillier_priv.decrypt(total_enc)

        summary.append({
            "seller": seller,
            "transaction_count": len(tx_list),
            "total_plain_sum": total_plain,
            "total_decrypted_amount": decrypted_total
        })

    return summary


# ============================================================
# 3️⃣ Digital Signature Generation (RSA + SHA-256)
# ============================================================

def sign_summary(summary, rsa_priv):
    """Sign the SHA-256 hash of the transaction summary."""
    summary_json = json.dumps(summary, indent=2)
    hash_obj = SHA256.new(summary_json.encode())
    signature = pkcs1_15.new(rsa_priv).sign(hash_obj)
    return signature, summary_json


# ============================================================
# 4️⃣ Server Main Function (Network I/O)
# ============================================================

def main():
    host = "127.0.0.1"
    port = 5003

    # Generate keys
    rsa_pub, rsa_priv = generate_rsa_keys()
    paillier_pub, paillier_priv = generate_paillier_keys()

    print("💳 Payment Gateway Server Running...")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
        srv.bind((host, port))
        srv.listen(1)
        conn, addr = srv.accept()

        with conn:
            print(f"✅ Connected with {addr}")

            # Send Paillier public key (n) to client
            conn.sendall(str(paillier_pub.n).encode())
            conn.recv(1024)  # wait for ack

            # Receive encrypted transactions
            data = conn.recv(8192)
            transactions = json.loads(data.decode())

            # Compute totals
            summary = compute_totals(paillier_pub, paillier_priv, transactions)

            # Sign the summary
            signature, summary_json = sign_summary(summary, rsa_priv)

            # Prepare payload to send
            payload = json.dumps({
                "summary": summary,
                "signature": signature.hex(),
                "rsa_pub": rsa_pub.export_key().decode()
            })
            conn.sendall(payload.encode())

            print("\n📦 Sent Signed Summary to Client.")
            print("🧾 Transaction Summary:")
            print(summary_json)


if __name__ == "__main__":
    main()
