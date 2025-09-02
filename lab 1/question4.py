import numpy as np
def hill_encrypt(plaintext,key):
    plaintext = ''.join(filter(str.isalpha,plaintext)).upper()
    numbers = [ord(char)-ord('A') for char in plaintext]
    if len(numbers) % 2!=0:
        numbers.append(ord('X')-ord('A'))
    plaintext_matrix = np.array(numbers).reshape(-1,2).T
    encrypted_matrix = (np.dot(key,plaintext_matrix)%26)
    encrypted_numbers = encrypted_matrix.T.flatten()
    cipherText = ''.join(chr(num+ord('A')) for num in encrypted_numbers)
    return cipherText
key = np.array([[3,3],[2,7]])
message = "We live in an insecure world"
encrypted_data = hill_encrypt(message,key)
print("Ciphered Data:",encrypted_data)

