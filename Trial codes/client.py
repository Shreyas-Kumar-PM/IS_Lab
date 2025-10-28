import socket
import json
from phe import paillier
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


# ============================================================
# 1️⃣ Prepare Seller Transactions
# ============================================================

def prepare_transactions(paillier_pub):
    """Encrypt transaction amounts for multiple sellers."""
    sellers = {
        "Seller_A": [100, 250],
        "Seller_B": [150, 200, 50]
    }

    encrypted_data = {}
    for seller, amounts in sellers.items():
        encrypted_data[seller] = []
        for amt in amounts:
            enc_val = paillier_pub.encrypt(amt)
            encrypted_data[seller].append((enc_val.ciphertext(), amt))
    return encrypted_data


# ============================================================
# 2️⃣ Verify Digital Signature (RSA + SHA-256)
# ============================================================

def verify_signature(summary, signature_hex, rsa_pub_pem):
    """Verify the digital signature received from server."""
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
# 3️⃣ Client Main Function (Network I/O)
# ============================================================

def main():
    host = "127.0.0.1"
    port = 5003

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        cli.connect((host, port))

        # Receive Paillier public key (n)
        n_val = int(cli.recv(4096).decode())
        paillier_pub = paillier.PaillierPublicKey(n_val)
        cli.sendall(b"ACK")

        # Prepare and send transactions
        encrypted_data = prepare_transactions(paillier_pub)
        cli.sendall(json.dumps(encrypted_data).encode())

        # Receive summary + signature
        response = cli.recv(8192)
        resp_data = json.loads(response.decode())

        summary = resp_data["summary"]
        signature = resp_data["signature"]
        rsa_pub_pem = resp_data["rsa_pub"]

        # Verify signature
        is_valid = verify_signature(summary, signature, rsa_pub_pem)

        print("\n=== 💰 Transaction Summary ===")
        print(json.dumps(summary, indent=2))
        print(f"\n🔐 Digital Signature Verification: {'✅ VALID' if is_valid else '❌ INVALID'}")


if __name__ == "__main__":
    main()
