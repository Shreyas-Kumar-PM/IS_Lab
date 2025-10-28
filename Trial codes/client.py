import socket
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

def paillier_encrypt(n, g, m):
    from Crypto.Random import random
    n2 = n * n
    r = random.StrongRandom().randint(1, n - 1)
    return (pow(g, m, n2) * pow(r, n, n2)) % n2

def main() -> None:
    host = "127.0.0.1"
    port = 5005

    seller_name = input("Enter Seller Name: ")
    transactions = list(map(int, input("Enter transaction amounts (space-separated): ").split()))

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cli:
        cli.connect((host, port))

        # Step 1: Receive public keys
        plen = int.from_bytes(cli.recv(4), "big")
        pdata = cli.recv(plen)
        keys = json.loads(pdata.decode())
        n = int(keys["paillier_n"])
        g = int(keys["paillier_g"])
        rsa_pub = RSA.import_key(keys["rsa_pub"])

        # Step 2: Encrypt transactions using Paillier
        enc_tx = [str(paillier_encrypt(n, g, amt)) for amt in transactions]
        seller_payload = {
            "seller_name": seller_name,
            "transactions_plain": transactions,
            "transactions_encrypted": enc_tx
        }

        msg = json.dumps(seller_payload).encode()
        cli.sendall(len(msg).to_bytes(4, "big") + msg)

        # Step 3: Receive ACK
        alen = int.from_bytes(cli.recv(4), "big")
        ack = cli.recv(alen).decode()
        print(f"[CLIENT] Server replied: {ack}")

        print("\n[CLIENT] Transactions Encrypted and Sent Successfully!")
        for i, (p, e) in enumerate(zip(transactions, enc_tx)):
            print(f"  Tx{i+1}: {p} -> Ciphertext (truncated): {e[:60]}...")

    print("\n[CLIENT] Waiting for server's signed summary (see server output).")

if __name__ == "__main__":
    main()
