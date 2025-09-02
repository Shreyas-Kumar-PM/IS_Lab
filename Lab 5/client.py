import socket

def dynamic_hash(data: bytes) -> int:
    length = len(data)
    initial_hash = length + 5000
    multiplier = (sum(data) % 100) + 1
    bit_size = 32
    bit_mask = (1 << bit_size) - 1

    hash_value = initial_hash
    for byte in data:
        hash_value = (hash_value * multiplier) + byte
        hash_value = hash_value ^ (hash_value >> (bit_size // 2))
    return hash_value & bit_mask

def send_data_and_verify(data_str, host='localhost', port=65432, corrupt=False):
    data_bytes = data_str.encode()
    if corrupt:
        # Introduce corruption by flipping a byte
        data_bytes = bytearray(data_bytes)
        if len(data_bytes) > 0:
            data_bytes[0] ^= 0xFF  # Flip bits of first byte
        data_bytes = bytes(data_bytes)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((host, port))
        s.sendall(data_bytes)

        received_hash_bytes = s.recv(1024)
        received_hash = int(received_hash_bytes.decode())

        local_hash = dynamic_hash(data_bytes)

        print(f"Sent data: {data_bytes.decode(errors='replace')}")
        print(f"Received hash from server: {received_hash}")
        print(f"Locally computed hash: {local_hash}")

        if received_hash == local_hash:
            print("Integrity check PASSED: Data is intact.")
        else:
            print("Integrity check FAILED: Data was corrupted or tampered.")

if __name__ == "__main__":
    # Test normal transmission
    print("=== Test normal transmission ===")
    send_data_and_verify("Hello, secure world!")

    # Test corrupted transmission
    print("\n=== Test corrupted transmission ===")
    send_data_and_verify("Hello, secure world!", corrupt=True)