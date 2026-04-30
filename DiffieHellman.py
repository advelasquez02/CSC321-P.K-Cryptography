import random
from Crypto.Hash import SHA256


#create Diffie-Hellman exchange to make key then use that key to do AES-CBC

# q = mod and a = base
q = 37
a = 5

def alice(x_a, y_b):
    #random integer for exponent in the range 2 to q-1
    s = pow(y_b,x_a,q)
    return s

def bob(x_b, y_a):
    s = pow(y_a,x_b,q)
    return s

if __name__ == '__main__':
    x_a = random.randint(1,q-1)
    y_a = pow(a,x_a,q)

    x_b = random.randint(1,q-1)
    y_b = pow(a,x_b,q)

    s_alice = alice(x_a, y_b)
    s_bob = bob(x_b, y_a)

    k = SHA256.new(s_alice.to_bytes((s_alice.bit_length() + 7) // 8, 'big')).digest()

    


