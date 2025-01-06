import maths

def RSA():
    """
    RSA algorithm
    returns the public and private keys
    """
    p = maths.random_prime(512)
    q = maths.random_prime(512)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    e = 65537
    d = maths.bezout(e, phi_n)
    d = d % phi_n

    return ((e, n), (d, n))


def text_to_int(text):
    """
    Convert a UTF-8 text into an int with UTF-8
    """
    return int.from_bytes(text.encode('utf-8'), byteorder='big')

def split_text_into_blocks(text, block_size):
    """
    Cut a text in blocks of given size (in bytes).
    Each block need to be smaller than 'n' (RSA module)
    """
    blocks = [text[i:i + block_size] for i in range(0, len(text), block_size)]
    return blocks

def encrypt_block(block, pk):
    """
    Encrypt a single block of text.
    """
    m = text_to_int(block)
    return pow(m, pk[0], pk[1])

def encrypt_text(text, pk, block_size=128):
    """
    Encrypt a text cutting it in blocks. Because if the text converted in int is bigger than 'n' the expansion
    cannot work properly.
    """
    blocks = split_text_into_blocks(text, block_size)
    encrypted_blocks = [encrypt_block(block, pk) for block in blocks]
    return encrypted_blocks

def int_to_text(integer):
    """
    Convert int to text (UTF-8).
    integer is supposed to be the result of text_to_int
    """
    byte_length = (integer.bit_length() + 7) // 8  # Taille en octets
    return integer.to_bytes(byte_length, byteorder='big').decode('utf-8', errors='ignore')

def read_file(file_path):
    """
    Read a file and return content as string
    """
    with open(file_path, 'r') as file:
        return file.read()

def decrypt_block(c, sk):
    """
    Decrypt a single block of crypted text
    """
    m = pow(c, sk[0], sk[1])
    return int_to_text(m)

def decrypt_text(encrypted_blocks, sk, block_size=128):
    """
    Decrypt text by combining all blocks together
    """
    decrypted_blocks = [decrypt_block(c, sk) for c in encrypted_blocks]
    return ''.join(decrypted_blocks)

def main():
    file_path = 'test.txt' 
    text = read_file(file_path)
    pk, sk = RSA()

    encrypted_message = encrypt_text(text, pk)

    print("Texte original :")
    print(text)
    print("\nMessage chiffré :")
    print(encrypted_message)

    # Déchiffrement du message
    decrypted_message = decrypt_text(encrypted_message, sk)

    print("\nMessage déchiffré :")
    print(decrypted_message)


if __name__ == "__main__":
    main()