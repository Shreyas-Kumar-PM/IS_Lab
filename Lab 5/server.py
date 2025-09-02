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

def start_server(host='localhost', port=65432):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print(f"Server listening on {host}:{port}...")
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")
            data = conn.recv(4096)
            if not data:
                print("No data received.")
                return

            print(f"Received data: {data.decode(errors='replace')}")
            hash_value = dynamic_hash(data)
            print(f"Computed hash: {hash_value}")

            # Send hash back to client as string
            conn.sendall(str(hash_value).encode())

if __name__ == "__main__":
    start_server()
