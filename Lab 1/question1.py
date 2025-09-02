def letter_to_num(letter):
    return ord(letter)-ord('A')

def num_to_letter(num):
    return chr(num+ord('A'))

def additive_encrypt(text,key):
    result = ""
    for char in text:
        num = letter_to_num(char)
        encrypted_data = (num+key)%26
        result += num_to_letter(encrypted_data)
    return result

def additive_decrypt(text,key):
    result = ""
    for char in text:
        num = letter_to_num(char)
        decrypted_data = (num-key)%26
        result += num_to_letter(decrypted_data)
    return result
def mod_inverse(a,m=26):
    a = a%m
    for x in range(1,m):
        if (a*x)%m == 1:
            return x
    return None
def multiplicative_encrypt(text,key):
    result = ""
    for char in text:
        num = letter_to_num(char)
        encrypted_data = (num*key)%26
        result += num_to_letter(encrypted_data)
    return result
def multiplicative_decrypt(text,key):
    result = ""
    inverse_key = mod_inverse(key,26)
    for char in text:
        num = letter_to_num(char)
        decrypted_data = (num*inverse_key)%26
        result += num_to_letter(decrypted_data)
    return result
def affine_encrypt(text,a,b):
    result = ""
    for char in text:
        num = letter_to_num(char)
        encrypted_data = (num*a+b)%26
        result += num_to_letter(encrypted_data)
    return result
def affine_decrypt(text,a,b):
    result = ""
    a_inverse = mod_inverse(a, 26)
    for char in text:
        num = letter_to_num(char)
        decrypted_data = (a_inverse*(num-b))%26
        result += num_to_letter(decrypted_data)
    return result
if __name__ == "__main__":
    plaintext = "I am learning information security".replace(" ","").upper();
    print("Plaintext :",plaintext)
    add_key = 20
    encrypted_add_data = additive_encrypt(plaintext,add_key)
    print("Encrypted :",encrypted_add_data)
    decrypted_add_data = additive_decrypt(encrypted_add_data,add_key)
    print("Decrypted :",decrypted_add_data)

    mul_key = 15
    encrypted_mul_data = multiplicative_encrypt(plaintext,mul_key)
    print("Encrypted :",encrypted_mul_data)
    decrypted_mul_data = multiplicative_decrypt(encrypted_mul_data,mul_key)
    print("Decrypted :",decrypted_mul_data)

    a_key = 15
    b_key = 20
    encrypted_affine_data = affine_encrypt(plaintext,a_key,b_key)
    print("Encrypted :",encrypted_affine_data)
    decrypted_affine_data = affine_decrypt(encrypted_affine_data,a_key,b_key)
    print("Decrypted :",decrypted_affine_data)
    print("Program Executed!")