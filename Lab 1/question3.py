def generate_playfair_matrix(key):
    key = ''.join(sorted(set(key.upper()), key=key.upper().index))
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    matrix = []

    for char in key:
        if char not in matrix and char != 'J':
            matrix.append(char)

    for char in alphabet:
        if char not in matrix and char != 'J':
            matrix.append(char)

    playfair_matrix = [matrix[i:i+5] for i in range(0, len(matrix), 5)]
    return playfair_matrix

def find_pos(matrix, char):
    for row_idx, row in enumerate(matrix):
        if char in row:
            col_idx = row.index(char)
            return row_idx, col_idx
    return None

def prepare_text(text):
    text = ''.join(filter(str.isalpha, text.upper()))
    text = text.replace('J', 'I')
    pairs = []
    i = 0
    while i < len(text):
        if i + 1 < len(text) and text[i] != text[i+1]:
            pairs.append(text[i:i+2])
            i += 2
        else:
            pairs.append(text[i]+'X')
            i += 1
    return pairs

def playfair_en(ptext, pfk):
    matrix = generate_playfair_matrix(pfk)
    ptext_pairs = prepare_text(ptext)

    ctext = []
    for pair in ptext_pairs:
        r1, c1 = find_pos(matrix, pair[0])
        r2, c2 = find_pos(matrix, pair[1])

        if r1 == r2:
            ctext.append(matrix[r1][(c1 + 1) % 5] + matrix[r2][(c2 + 1) % 5])
        elif c1 == c2:
            ctext.append(matrix[(r1 + 1) % 5][c1] + matrix[(r2 + 1) % 5][c2])
        else:
            ctext.append(matrix[r1][c2] + matrix[r2][c1])

    return ''.join(ctext)

def playfair_de(ctext, pfk):
    matrix = generate_playfair_matrix(pfk)
    ctext_pairs = prepare_text(ctext)

    ptext = []
    for pair in ctext_pairs:
        r1, c1 = find_pos(matrix, pair[0])
        r2, c2 = find_pos(matrix, pair[1])

        if r1 == r2:
            ptext.append(matrix[r1][(c1 - 1) % 5] + matrix[r2][(c2 - 1) % 5])
        elif c1 == c2:
            ptext.append(matrix[(r1 - 1) % 5][c1] + matrix[(r2 - 1) % 5][c2])
        else:
            ptext.append(matrix[r1][c2] + matrix[r2][c1])

    return ''.join(ptext)

def main():
    ptext = input("Kindly enter your desired plaintext: ")
    pfk = input("Kindly enter the Playfair Key: ")

    print("Welcome to the Playfair cipher system.")
    print("Plaintext: ", ptext)
    print("Playfair Key: ", pfk)
    ctext = playfair_en(ptext, pfk)
    print("Ciphertext: ", ctext)
    decrypted_text = playfair_de(ctext, pfk)
    print("Decrypted Text: ", decrypted_text)

if __name__ == '__main__':
    main()