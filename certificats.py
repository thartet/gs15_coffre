from sha256 import sha256
from zpk import generate_keys
import rsa

class SimpleCA:
    def __init__(self, ca_private_key):
        """
        Initialize the Certificate Authority with the private key.
        ca_private_key : the private key of the CA
        """
        self.ca_private_key = ca_private_key


    def issue_certificate(self, username, public_key):
        """
        Issues a certificate for the given username and public key.
        username : the username of the user
        public_key : the public key of the user
        returns the certificate
        """
        certificate = self.sign_certificate(public_key)
        print(f"Certificate for {username} issued.")
        return certificate
    

    def sign_certificate(self, public_key):
        """
        Signs the public key (hash of the public key) using the CA's private RSA key.
        public_key : the public key to sign
        returns the public key and the signature
        """
        public_key_hash = sha256(str(public_key).encode())
        signature = self.sign(public_key_hash)
        print(f"Certificate signed with signature {signature}")
        return {'public_key': public_key, 'signature': signature}
    

    def sign(self, data_hash):
        """
        Signs the data hash using the CA's private key with RSA encryption.
        data_hash : the hash of the data to sign
        returns the signature
        """
        data_int = int.from_bytes(data_hash, byteorder='big')
        signature = rsa.encryptRsa(data_int, self.ca_private_key)
        print(f"Signature created: {signature}")
        return signature
    

    def verify_certificate(self, certificate, ca_public_key):
        """
        Verifies the certificate using the CA's public key.
        certificate : the certificate to verify
        ca_public_key : the public key of the CA
        returns if the certificate is valid
        """
        public_key = certificate['public_key']
        public_key_hash = int.from_bytes(sha256(str(public_key).encode()), byteorder='big')
        signature = certificate['signature']
        print(f"Verifying certificate with signature {signature}")
        print(f"Public key hash {public_key_hash}")
        return self.verify(public_key_hash, signature, ca_public_key)
    

    def verify(self, data_hash, signature, ca_public_key):
        """
        Verify the signature using the CA's public key.
        data_hash : the hash of the data
        signature : the signature to verify
        ca_public_key : the public key of the CA
        returns if the signature is valid
        """
        print(f"Verifying signature with data hash {data_hash}")
        decrypted_signature = rsa.decryptRsa(signature, ca_public_key)
        print(f"Decrypted signature: {decrypted_signature}")
        return decrypted_signature == data_hash


def generate_keys():
    """
    Generate RSA public/private key pair.
    returns the public key and private key
    """
    public_key, private_key = rsa.RSA()
    return public_key, private_key


def main():
    with open('.keys_server/rsa.pub', 'rb') as pub_file:
        pub = pub_file.read()
        tab = pub.split(b'\n')
        pub = (int(tab[0].decode()), int(tab[1].decode()))
        print(pub)

    with open('.keys_server/rsa', 'rb') as priv_file:
        priv = priv_file.read()
        tab = priv.split(b'\n')
        priv = (int(tab[0].decode()), int(tab[1].decode()))
        print(priv)

    ca_private_key = priv
    ca_public_key = pub
    ca = SimpleCA(ca_private_key)
    
    # Issuing a certificate
    username = "Alice"
    public_key = pub
    certificate = ca.issue_certificate(username, public_key)
    
    # Verifying the certificate
    print(f"Certificate: {certificate}")
    print(ca.verify_certificate(certificate, ca_public_key))


if __name__ == "__main__":
    main()