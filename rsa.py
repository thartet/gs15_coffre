import maths
import os
import base64

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

def encryptRsa(m, pk):
    """
    Encrypt a message with a public key
    """
    return pow(m, pk[0], pk[1])

def decryptRsa(c, sk):
    """
    Decrypt a message with a private key
    """
    return pow(c, sk[0], sk[1])

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

def testRSA():
    main()

def generate_keyfiles():
    """
    Generate RSA public/private key pair.
    """
    public_key, private_key = RSA()
    os.makedirs('.keys_client', exist_ok=True)

    pub_key_b64 = base64.b64encode(f"{public_key[0]}\n{public_key[1]}".encode()).decode()
    with open('.keys_client/rsa.pub', 'w') as pub_file:
        pub_file.write("ssh-rsa ")
        for i in range(0, len(pub_key_b64), 64):
            pub_file.write(pub_key_b64[i:i+64] + '\n')

    priv_key_b64 = base64.b64encode(f"{private_key[0]}\n{private_key[1]}".encode()).decode()
    with open('.keys_client/rsa', 'w') as priv_file:
        priv_file.write("-----BEGIN RSA PRIVATE KEY-----\n")
        for i in range(0, len(priv_key_b64), 64):
            priv_file.write(priv_key_b64[i:i+64] + '\n')
        priv_file.write("-----END RSA PRIVATE KEY-----\n")
    
    print("Keys generated. They can be found in the .keys_client directory.")

if __name__ == "__main__":
    main()