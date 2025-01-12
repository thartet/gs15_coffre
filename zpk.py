import random
from maths import random_prime, random_generator


class Schnorr:
    def __init__(self, pub, s, p, alpha):
        """ Initialize the Schnorr object
        pub : public key
        s : secret key
        p : prime number
        alpha : generator
        """
        self._pub = pub
        self._s = s
        self._p = p
        self._alpha = alpha

    def nicolas_choosing_m(self):
        """Nicolas chooses m and computes M."""
        m = random.randint(1, self._p-1)
        M = pow(self._alpha, m, self._p)
        print(f"Nicolas chose m = {m} and calculated M = {M}")
        return m, M

    def remi_choosing_r(self):
        """Rémi chooses r."""
        r = random.randint(1, self._p-1)
        print(f"Rémi chose r = {r}")
        return r

    def nicolas_proving(self, m, r):
        """Nicolas calculates the proof for message m."""
        proof = (m - r * self._s) % (self._p - 1)
        print(f"Nicolas proves m with proof = {proof}")
        return proof

    def remi_veryfing(self, proof, r, M):
        """
        Rémi verifies the proof
        returns if the proof is valid
        """
        verification = (pow(self._alpha, proof, self._p) * pow(self._pub, r, self._p)) % self._p
        print(f"Rémi verifies the proof with verification = {verification}")
        print(f"The proof is valid : {verification == M}")
        return verification == M


def generate_keys(p, prk):
    """
    Generate related public and private keys.
    returns the public key, the private key, the prime number and the generator
    """
    alpha = random_generator(p)
    pub = pow(alpha, prk, p)  # public key
    return pub, alpha


def main():
    # Key generation
    p = random_prime(256)
    prk = random.randint(1, p - 1) 
    pub, alpha = generate_keys(p, prk)
    print(f"Generated public key: {pub}")
    print(f"Generated private key: {prk}")

    schnorr = Schnorr(pub, prk, p, alpha)
    
    m, M = schnorr.nicolas_choosing_m()
    r = schnorr.remi_choosing_r()
    proof = schnorr.nicolas_proving(m, r)
    valid = schnorr.remi_veryfing(proof, r, M)
    print(f"Proof valid: {valid}")

def testZpk():
    """
    Test the ZPK algorithm
    """
    main()
