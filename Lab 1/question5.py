def find_shift_key(plaintext,ciphertext):
    p_num = ord(plaintext[0].upper()) - ord('A')
    c_num = ord(ciphertext[0].upper()) - ord('A')

    shift_key = (c_num-p_num) % 26
    return shift_key

def decrypt_cipher(ciphertext,key):
    decrypted = []
    for char in ciphertext:
        if char.isalpha():
            shifted = (ord(char.upper()) - ord('A')-key) % 26
            decrypted.append(chr(shifted+ord('a')))
        else:
            decrypted.append(char)
    return ''.join(decrypted)
def main():
    known_text = "yes"
    known_cipher = "CIW"

    new_cipher = "XVIEWYWI"
    key = find_shift_key(known_text,known_cipher)

    plaintext = decrypt_cipher(new_cipher,key)
    print("The text is :",plaintext)
    print("Program executed!")

if __name__ == "__main__":
    main()
