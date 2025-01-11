import random
from sha256 import *
P = 1299827
G = 423

def genPublicAndPrivateKey(IP):
    """
    Generate the public and private keys for the Diffie-Hellman algorithm
    IP: the IP of the user
    returns the public and private keys
    """
    privateKey = random.randint(1, 10000)
    print("Private Key of ", IP, " is : ", privateKey)
    publicKey = pow(G, privateKey) % P
    print("Public Key of ", IP, " is : ", publicKey)
    return publicKey, privateKey

def genSecretKey(otherPublicKey, privateKey):
    """
    Generate the secret key for the Diffie-Hellman algorithm
    otherPublicKey: the public key of the other user
    privateKey: the private key of the user
    returns the secret key
    """
    secretKey = pow(otherPublicKey, privateKey) % P
    secretKey = sha256(secretKey.to_bytes(16, 'big')).hex()
    secretKey = format(int(secretKey, 16), '0256b')
    print("Secret Key is: ", secretKey)
    return secretKey

def testDF():
    """
    Test the Diffie-Hellman algorithm
    """
    puk1, prk1 = genPublicAndPrivateKey("127.0.0.1")
    puk2, prk2 = genPublicAndPrivateKey("127.0.0.2")
    sk1 = genSecretKey(puk2, prk1)
    sk2 = genSecretKey(puk1, prk2)

