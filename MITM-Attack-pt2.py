import random
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

q = int(
    "B10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
    "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
    "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
    "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
    "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
    "DF1FB2BC2E4A4371", 16
)

a = int(
    "A4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
    "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
    "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
    "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
    "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
    "855E6EEB22B3B2E5", 16
)

# q,a = 37, 5
IV = get_random_bytes(16)

class Alice:
    def keygen(self):
        # random integer for exponent in the range 2 to q-1
        self.x_a = random.randint(1, q - 1)
        # compute public key to send to bob
        self.y_a = pow(a, self.x_a, q)
        return self.y_a

    def encrypt(self, y_b):
        # compute shared secret
        s = pow(y_b, self.x_a, q)
        # hash the key and truncate to 16 bits
        k = SHA256.new(str(s).encode()).digest()[:16]
        # raw byte string
        return AES.new(k, AES.MODE_CBC, IV).encrypt(pad(b"Hi Bob!", 16))

class Bob:
    def keygen(self):
        # random integer for exponent in the range 2 to q-1
        self.x_b = random.randint(1, q - 1)
        # compute public key to send to alice
        self.y_b = pow(a, self.x_b, q)
        return self.y_b

    def encrypt(self, y_a):
        # compute shared secret
        s = pow(y_a, self.x_b, q)
        # hash the key and truncate to 16 bits
        k = SHA256.new(str(s).encode()).digest()[:16]
        # raw byte string
        return AES.new(k, AES.MODE_CBC, IV).encrypt(pad(b"Hi Alice!", 16))

class Mallory:
    def intercept(self, alice, bob):
        #we can alter alpha or in our case "a" and then create alice and bobs keys.
        #there are 3 cases 1) a = 1, then  y_b = 1 always (1 ^ x mod q = 1)
        #2) if a = q then y_a = 0 (q ^ x mod q = 0)
        #3) if a = q -1 then y_a will be either q - 1 or 1 depending on x being odd or even
        global a
        a = 1

        alice.keygen()
        bob.keygen()

        if a == 1:
            alice_txt = alice.encrypt(bob.y_b)
            bob_txt = bob.encrypt(alice.y_a)
            k = SHA256.new(str(1).encode()).digest()[:16]
            plaintext_a = unpad(AES.new(k, AES.MODE_CBC, IV).decrypt(alice_txt), 16).decode()
            plaintext_b = unpad(AES.new(k, AES.MODE_CBC, IV).decrypt(bob_txt),16).decode()


        elif a == q:
            alice_txt = alice.encrypt(bob.y_b)
            bob_txt = bob.encrypt(alice.y_a)
            k = SHA256.new(str(0).encode()).digest()[:16]
            plaintext_a = unpad(AES.new(k, AES.MODE_CBC, IV).decrypt(alice_txt), 16).decode()
            plaintext_b = unpad(AES.new(k, AES.MODE_CBC, IV).decrypt(bob_txt), 16).decode()


        elif a == (q - 1):
            alice_txt = alice.encrypt(bob.y_b)
            bob_txt = bob.encrypt(alice.y_a)

            #two options, 1 or q - 1
            k1 = SHA256.new(str(1).encode()).digest()[:16]
            k2 = SHA256.new(str(q-1).encode()).digest()[:16]
            try:
                plaintext_a = unpad(AES.new(k1, AES.MODE_CBC, IV).decrypt(alice_txt), 16).decode()
            except:
                plaintext_a = unpad(AES.new(k2, AES.MODE_CBC, IV).decrypt(alice_txt), 16).decode()

            try:
                plaintext_b = unpad(AES.new(k1, AES.MODE_CBC, IV).decrypt(bob_txt), 16).decode()
            except:
                plaintext_b = unpad(AES.new(k2, AES.MODE_CBC, IV).decrypt(bob_txt), 16).decode()



        return plaintext_a, plaintext_b

if __name__ == '__main__':
    alice = Alice()
    bob = Bob()
    mallory = Mallory()

    plaintext_a, plaintext_b = mallory.intercept(alice, bob)
    print("Mallory got the plaintexts: " + plaintext_a + " " + plaintext_b)