

from Crypto.Util import number

p =  number.getPrime(256)
q  = number.getPrime(256)

#check to make sure they are not equal
if p == q:
    q = number.getPrime(256)

n = p * q
e = 65537
phi =  (p-1) * (q -1)
#where a = e and b  phi(n)
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

# sanity check
assert (e * d) % phi == 1, "modular inverse is wrong!"

public_key = {'e':e,'n':n}
private_key = {'d': d,'n': n}

def string_to_int(message):
    return int(message.encode('utf-8').hex(), 16)

def encrypt(message, public_key):
    m = string_to_int(message)
    if m >= public_key['n'] or (m < 0):
        return ValueError("Message must be less than or equal to n")
    return pow(m,public_key['e'],public_key['n'])

#helper function to turn int into string after decoding
def int_to_string(n):
    return bytes.fromhex(hex(n)[2:]).decode('utf-8')

def decrypt(cipherTxt, private_key):
    return int_to_string(pow(cipherTxt,private_key['d'],private_key['n']))

if __name__ == '__main__':
    message = "Hi Angel, this is the secret message, lmk when you see this!"
    encrypted_message = encrypt(message, public_key)
    print(encrypted_message)
    print(decrypt(encrypted_message, private_key))




