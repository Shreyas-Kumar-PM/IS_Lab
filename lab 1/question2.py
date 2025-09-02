def letter_to_num(letter):
    return ord(letter) - ord('A')
def num_to_letter(num):
    return chr(num + ord('A'))
def encrypt_vigenere(plaintext, key):
    cipher = ""
    key = key.upper()
    key_length = len(key)
    for i,char in enumerate(plaintext):
        p_num = letter_to_num(char)
        k_num = letter_to_num(key[i%key_length])
        encrypted_data = (p_num+k_num)%26
        cipher += num_to_letter(encrypted_data)
    return cipher
def decrypt_vigenere(encrypted_data, key):
    cipher = ""
    key = key.upper()
    key_length = len(key)
    for i,char in enumerate(encrypted_data):
        p_num = letter_to_num(char)
        k_num = letter_to_num(key[i%key_length])
        decrypted_data = (p_num-k_num)%26
        cipher += num_to_letter(decrypted_data)
    return cipher
def encrypt_autokey(plaintext, key):
    cipher = ""
    key_stream = [key]
    for i,char in enumerate(plaintext):
        p_num = letter_to_num(char)
        k_num = key_stream[i]
        encrypted_data = (p_num+k_num)%26
        cipher += num_to_letter(encrypted_data)
        key_stream.append(p_num)
    return cipher
def decrypt_autokey(decrypted_data, key):
    cipher = ""
    key_stream = [key]
    for i,char in enumerate(decrypted_data):
        p_num = letter_to_num(char)
        k_num = key_stream[i]
        encrypted_data = (p_num-k_num)%26
        cipher += num_to_letter(encrypted_data)
        key_stream.append(encrypted_data)
    return cipher
if __name__ == "__main__":
    plaintext = "the house is being sold tonight".replace(" ","").upper();
    vigenere_key = "dollars"
    auto_key = 7

    print("Plaintext :",plaintext)
    vigenere_encrypted_data = encrypt_vigenere(plaintext, vigenere_key)
    print("Encrypted :",vigenere_encrypted_data)
    vigenere_decrypted_data = decrypt_vigenere(vigenere_encrypted_data, vigenere_key)
    print("Decrypted :",vigenere_decrypted_data)

    autokey_encrypted_data = encrypt_autokey(plaintext, auto_key)
    print("Encrypted :",autokey_encrypted_data)
    autokey_decrypted_data = decrypt_autokey(autokey_encrypted_data, auto_key)
    print("Decrypted :",autokey_decrypted_data)
    print("Program executed!")

