import gmpy2
from time import time
from Crypto.Util.number import getPrime


def gcd(a, b):
    while b > 0:
        a, b = b, a % b
    return a


def lcm(a, b):
    return a * b // gcd(a, b)


def int_time():
    return int(round(time() * 1000))


class PrivateKey(object):
    def __init__(self, p, q, n):
        self.l = (p - 1) * (q - 1)
        self.m = gmpy2.invert(self.l, n)


class PublicKey(object):

    @classmethod
    def from_n(cls, n):
        return cls(n)

    def __init__(self, n):
        self.n = n
        self.n_sq = n * n
        self.g = n + 1


def generate_keypair(bits):
    p_equal_q = True
    p = 0
    q = 0
    while p_equal_q:
        p = getPrime(bits // 2)
        q = getPrime(bits // 2)
        if p != q:
            p_equal_q = False
    n = p * q
    with open('PrivateKey', 'w') as f:
        f.write(str(p) + ' ' + str(q) + ' ' + str(n))
    with open('PublicKey', 'w') as file:
        file.write(str(n))


def encrypt(pub, plain):
    one = gmpy2.mpz(1)
    state = gmpy2.random_state(int_time())
    r = gmpy2.mpz_random(state, pub.n)
    while gmpy2.gcd(r, pub.n) != one:
        state = gmpy2.random_state(int_time())
        r = gmpy2.mpz_random(state, pub.n)
    x = gmpy2.powmod(r, pub.n, pub.n_sq)
    cipher = gmpy2.f_mod(gmpy2.mul(gmpy2.powmod(pub.g, plain, pub.n_sq), x), pub.n_sq)
    return cipher


def decrypt(priv, pub, cipher):
    one = gmpy2.mpz(1)
    x = gmpy2.sub(gmpy2.powmod(cipher, priv.l, pub.n_sq), one)
    plain = gmpy2.f_mod(gmpy2.mul(gmpy2.f_div(x, pub.n), priv.m), pub.n)
    if plain >= gmpy2.f_div(pub.n, 2):
        plain = plain - pub.n
    return plain


while True:
    print("1 - generate keys\n 2 - encrypt text\n 3 - decrypt text\n 0 - Exit ")
    option = int(input("Enter option:"))

    if option == 1:
        bits = int(input("Enter size of keys:"))
        generate_keypair(bits)
    elif option == 2:
        n = int(open('PublicKey', 'r').read())
        plain = int(open('plaintext', 'r').read().replace('\n', '').replace(' ', ''))

        cipher = encrypt(PublicKey(n), plain)
        with open('encrypted', 'w') as f:
            f.write(str(cipher))
    elif option == 3:
        key = open('PrivateKey', 'r').read().split(' ')
        p = int(key[0])
        q = int(key[1])
        n = int(key[2])
        encrypted = int(open('encrypted', 'r').read())
        plain = decrypt(PrivateKey(p, q, n), PublicKey(n), encrypted)
        with open('decrypted', 'w') as f:
            f.write(str(plain))
    elif option == 0:
        break
