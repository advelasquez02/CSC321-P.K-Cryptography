from Crypto.Util import number
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

p = number.getPrime(256)
q = number.getPrime(256)

if p == q:
    q = number.getPrime(256)

n = p * q
e = 65537
phi = (p-1) * (q-1)

def extended_gcd(a, b):
    old_r = a
    r = b
    old_x = 1
    x = 0
    old_y = 0
    y = 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_x, x = x, old_x - q * x
        old_y, y = y, old_y - q * y
    return old_r, old_x, old_y

gcd, x, y = extended_gcd(e, phi)
d = x % phi

assert (e * d) % phi == 1, "modular inverse is wrong!"

public_key = {'e': e, 'n': n}
private_key = {'d': d, 'n': n}

def bob(public_key):
    s = number.getRandomRange(1, public_key['n'])
    c = pow(s, public_key['e'], public_key['n'])
    return s, c

def alice(c, private_key, message):
    s = pow(c, private_key['d'], private_key['n'])  # decrypts whatever c she receives
    k = SHA256.new(str(s).encode()).digest()
    cipher = AES.new(k, AES.MODE_CBC)
    c0 = cipher.encrypt(pad(message.encode(), AES.block_size))
    return c0, cipher.iv

def mallory(c0, iv):
    s_prime = 3

    k = SHA256.new(str(s_prime).encode()).digest()
    cipher = AES.new(k, AES.MODE_CBC, iv)
    decrypted = unpad(cipher.decrypt(c0), AES.block_size)
    print(decrypted.decode())
    return decrypted

if __name__ == '__main__':
    s, c = bob(public_key)

    # Mallory intercepts c and computes c'
    s_prime = 3
    c_prime = pow(s_prime, public_key['e'], public_key['n'])

    # Alice gets c' instead of Bob's c  ← pass c_prime here!
    c0, iv = alice(c_prime, private_key, "Hi Angel!")

    # Mallory decrypts using known s'
    mallory(c0, iv)