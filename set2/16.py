import base64
import binascii
import random
import os
from Crypto.Cipher import AES

KEY = os.urandom(16)
IV = os.urandom(16)

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

def detectadmin(s):
    return b';admin=true;' in s

def escape(s):
    return s.replace(b'%',b'%25').replace(b';',b'%3B').replace(b'=',b'%3D')

def encryption_oracle(s):
    s = b"comment1=cooking%20MCs;userdata=" + escape(s) + b";comment2=%20like%20a%20pound%20of%20bacon"
    s = pad(s)
    return cbcencrypt(s,IV,KEY)

def decryption_oracle(s):
    return cbcdecrypt(s,IV,KEY)

s = encryption_oracle(b'A'*16)
s2 = s[:32] + xor(xor(b';admin=true;AAAA',b";comment2=%20lik"),s[32:48]) + s[48:]

ds2 = decryption_oracle(s2)
if detectadmin(ds2):
    print(";admin=true; detected!")
else:
    print("no admin detected")
