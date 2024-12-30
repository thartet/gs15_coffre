import random
from sha256 import *
P = 1299827
G = 423

def genPublicAndPrivateKey(IP):
    privateKey = random.randint(1, 10000)
    print("Private Key of ", IP, " is : ", privateKey)
    publicKey = pow(G, privateKey) % P
    print("Public Key of ", IP, " is : ", publicKey)
    return publicKey, privateKey

def genSecretKey(otherPublicKey, privateKey):
    secretKey = pow(otherPublicKey, privateKey) % P
    secretKey = sha256(secretKey.to_bytes(16, 'big')).hex()
    secretKey = format(int(secretKey, 16), '0256b')
    print("Secret Key is: ", secretKey)
    return secretKey

