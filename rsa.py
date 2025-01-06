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


def encrypt(m, pk):
    """
    Encrypt a message
    m : message to encrypt (string)
    pk : public key
    returns the encrypted message (as a number)
    """
    m_int = int.from_bytes(m.encode(), 'big')
    return pow(m_int, pk[0], pk[1])


def decrypt(c, sk):
    """
    Decrypt a message
    c : encrypted message (number)
    sk : private key
    returns the decrypted message (as a string)
    """
    m_int = pow(c, sk[0], sk[1])
    m = m_int.to_bytes((m_int.bit_length() + 7) // 8, 'big').decode()
    return m


def encrypt_file(file, pk):
    """
    Encrypt a file
    file : file to encrypt
    pk : public key
    returns the encrypted file content
    """
    with open(file, "r") as f:
        content = f.read()
    encrypted_content = encrypt(content, pk)
    
    with open("encrypted_" + file, "w") as f:
        f.write(str(encrypted_content))
    
    return encrypted_content


def decrypt_file(file, sk):
    """
    Decrypt a file
    file : file to decrypt
    sk : private key
    returns the decrypted file content
    """
    with open(file, "r") as f:
        content = f.read()
    encrypted_content = int(content)
    decrypted_content = decrypt(encrypted_content, sk)
    
    with open("decrypted_" + file, "w") as f:
        f.write(decrypted_content)

    return decrypted_content


def main():
    pk, sk = RSA()
    
    # Encrypt and decrypt a file
    print("Encrypting file...")
    encrypted_content = encrypt_file("test.txt", pk)
    print(f"Encrypted content written to: encrypted_test.txt")
    print("\nDecrypting file...")
    decrypted_content = decrypt_file("encrypted_test.txt", sk)
    print(f"Decrypted content written to: decrypted_test.txt")
    print("Decrypted content:")
    print(decrypted_content)

if __name__ == "__main__":
    main()