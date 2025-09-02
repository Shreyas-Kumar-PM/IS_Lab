import hashlib
import random
import string
import time

def generate_random_strings(min_len=5, max_len=20, count_min=50, count_max=100):
    n = random.randint(count_min, count_max)
    dataset = []
    for _ in range(n):
        length = random.randint(min_len, max_len)
        s = ''.join(random.choices(string.ascii_letters + string.digits, k=length))
        dataset.append(s)
    return dataset

def compute_hashes(data, algorithm):
    hash_func = getattr(hashlib, algorithm)
    start_time = time.perf_counter_ns()  # Use perf_counter_ns for nanoseconds
    hashes = []
    for item in data:
        h = hash_func(item.encode()).hexdigest()
        hashes.append(h)
    elapsed = time.perf_counter_ns() - start_time
    return hashes, elapsed

def detect_collisions(hashes):
    seen = set()
    collisions = set()
    for h in hashes:
        if h in seen:
            collisions.add(h)
        else:
            seen.add(h)
    return collisions

def main():
    print("Generating random dataset...")
    dataset = generate_random_strings()
    print(f"Generated {len(dataset)} random strings.")

    algorithms = ['md5', 'sha1', 'sha256']
    results = {}

    for algo in algorithms:
        print(f"\nHashing with {algo.upper()}...")
        hashes, elapsed = compute_hashes(dataset, algo)
        collisions = detect_collisions(hashes)
        results[algo] = {
            'time_ns': elapsed,
            'collisions': collisions,
            'collision_count': len(collisions)
        }
        print(f"Time taken: {elapsed} nanoseconds")
        if collisions:
            print(f"Collisions detected ({len(collisions)}): {collisions}")
        else:
            print("No collisions detected.")

    print("\nSummary:")
    for algo, result in results.items():
        print(f"{algo.upper()}: Time = {result['time_ns']} ns, Collisions = {result['collision_count']}")

if __name__ == "__main__":
    main()