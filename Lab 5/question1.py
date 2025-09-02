def custom_hash(s: str) -> int:
    # Use the length of the input string + 5000 as a starting seed (instead of fixed 5381)
    initial_hash = len(s) + 5000

    # Use the sum of all ASCII values in the string mod 100 as multiplier + 1 (to avoid zero)
    multiplier = (sum(ord(c) for c in s) % 100) + 1

    # Use bit size of Python int (or 32 bits) dynamically for mask
    bit_size = 32
    bit_mask = (1 << bit_size) - 1

    hash_value = initial_hash
    for char in s:
        hash_value = (hash_value * multiplier) + ord(char)
        hash_value = hash_value ^ (hash_value >> (bit_size // 2))
    return hash_value & bit_mask


# Example usage
a=input("Enter the plaintext to be hashed: ")
print(custom_hash(a))