import random

def euclide(a, b):
    """
    Application of the Euclide theorem
    a, b : input numbers
    returns the greatest common divisor of a and b
    """
    if b == 0:
        return (a, 1, 0)
    else:
        (d, u, v) = euclide(b, a % b)
        return (d, v, u - (a // b) * v)

def bezout(a, b):
    """
    Application of the Bezout theorem
    a, b : input numbers
    returns the inverse of a modulo b
    """
    (d, u, v) = euclide(a, b)
    return u % b

def is_prime(n,k=10):
    """
    Miller-Rabin primality test
    n : input number
    k : number of iterations
    returns True if the number is prime
    returns False if the number is non prime
    """

    if n < 2:
        return False
    
    if n != 2 and n % 2 == 0:
        return False
    
    s = n - 1

    while s % 2 == 0:
        s = s // 2
    
    for i in range(k):
        a = random.randrange(2, n - 1)
        temp = s
        mod = pow(a, temp, n)
        while temp != n - 1 and mod != 1 and mod != n - 1:
            mod = (mod * mod) % n
            temp *= 2
            if mod != n - 1 and temp % 2 == 0:
                return False
        return True


def random_prime(bits) :
    """
    Generate a random prime number
    bits : The size in bits of the number to generate
    returns the number generated
    """
    while True : 
        rnumber = random.randrange(2**(bits-1), 2**(bits))
        if is_prime(rnumber):
            return rnumber

