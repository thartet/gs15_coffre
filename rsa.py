import maths

def RSA ():
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

    print("p :", p)
    print("q :", q)
    print("n :", n)
    print("d : ", d)
    print("Public key : ", (e, n))
    print("Private key :", (d, n))

    return ((e, n), (d, n))
    
def encrypt (m, pk):
    """
    Encrypt a message
    m : message to encrypt
    pk : public key
    returns the encrypted message
    """
    return pow(m, pk[0], pk[1])

def decrypt (c, sk):
    """
    Decrypt a message
    c : message to decrypt
    sk : private key
    returns the decrypted message
    """
    return pow(c, sk[0], sk[1])


def main():
    pk, sk = RSA()
    result = encrypt(5,pk)
    print("The encrypted message is :", result)
    print("The decrypted message is : ", decrypt(result, sk))


if __name__ == "__main__":
    main()