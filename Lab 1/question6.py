from math import gcd


# Convert letter to number
def letter_to_num(c):
    return ord(c.upper()) - ord('A')


# Convert number to letter
def num_to_letter(n):
    return chr(n + ord('A'))


# Modular inverse of a mod m (using Extended Euclidean Algorithm)
def modinv(a, m=26):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None


# Affine cipher encryption: E(x) = (a*x + b) mod 26
def affine_encrypt(x, a, b):
    return (a * x + b) % 26


# Affine cipher decryption: D(y) = a_inv * (y - b) mod 26
def affine_decrypt(y, a_inv, b):
    return (a_inv * (y - b)) % 26


# Known plaintext-ciphertext pair
plaintext_pair = "ab"
ciphertext_pair = "GL"

# Convert known pairs to numbers
p0, p1 = [letter_to_num(c) for c in plaintext_pair]
c0, c1 = [letter_to_num(c) for c in ciphertext_pair]

# Given ciphertext to decrypt
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"


# Brute force all valid a (coprime with 26) and all b from 0 to 25
def brute_force_affine():
    for a in range(1, 26):
        if gcd(a, 26) != 1:
            continue  # a must be coprime with 26
        a_inv = modinv(a, 26)
        if a_inv is None:
            continue

        # Solve for b using one pair: c0 = (a * p0 + b) mod 26 => b = (c0 - a*p0) mod 26
        b = (c0 - a * p0) % 26

        # Check if second pair matches: c1 == (a * p1 + b) mod 26
        if (a * p1 + b) % 26 == c1:
            # Keys found, decrypt full ciphertext
            plaintext_nums = []
            for char in ciphertext:
                y = letter_to_num(char)
                x = affine_decrypt(y, a_inv, b)
                plaintext_nums.append(x)

            plaintext = ''.join(num_to_letter(n) for n in plaintext_nums)
            return a, b, plaintext

    return None, None, None


a, b, decrypted_text = brute_force_affine()

if decrypted_text:
    print(f"Found keys: a = {a}, b = {b}")
    print(f"Decrypted text: {decrypted_text.lower()}")
else:
    print("No valid keys found.")
