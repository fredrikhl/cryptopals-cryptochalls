import base64
import binascii
import random
import os
from Crypto.Cipher import AES

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

def pad(s, blocksize=16):
    l = (blocksize - len(s) - 1) % blocksize + 1
    return s + bytes([l]*l)

def cbcencrypt(s,iv,key):
    blocks = [s[i:i+16] for i in range(0,len(s),16)]
    prevblock = iv
    ciphertext = b''
    for block in blocks:
        block = xor(prevblock, block)
        block = AES.new(key, AES.MODE_ECB).encrypt(block)
        prevblock = block
        ciphertext += block
    return ciphertext

def cbcdecrypt(s,iv,key):
    blocks = [s[i:i+16] for i in range(0,len(s),16)]
    prevblock = iv
    plaintext = b''
    for block in blocks:
        block2 = AES.new(key, AES.MODE_ECB).decrypt(block)
        block2 = xor(prevblock, block2)
        prevblock = block
        plaintext += block2
    return plaintext

def ecbencrypt(s,key):
    return AES.new(key, AES.MODE_ECB).encrypt(s)

def ecbdecrypt(s,key):
    return AES.new(key, AES.MODE_ECB).decrypt(s)

def encryption_oracle(s):
    s = os.urandom(random.randrange(5,10)) + s + os.urandom(random.randrange(5,10))
    s = pad(s)
    key = os.urandom(16)
    if random.random() < 0.5:
        iv = os.urandom(16)
        print("Using CBC")
        return cbcencrypt(s,iv,key)
    else:
        print("Using ECB")
        return ecbencrypt(s,key)

def detectecb(s):
    l = [s[i:i+16] for i in range(0,len(s),16)]
    for i in l:
        if l.count(i) > 1:
            return True
    return False

for i in range(20):
    s = encryption_oracle(b'A'*48)
    if detectecb(s):
        print("Detected ECB")
    else:
        print("Detected CBC")
    print()
