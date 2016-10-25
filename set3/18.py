import base64
import binascii
import random
import os
import struct
from Crypto.Cipher import AES

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

def p64(i):
    return struct.pack("<q",i)

def ctrencrypt(s,nonce,key):
    blocks = [s[i:i+16] for i in range(0,len(s),16)]
    ciphertext = b''
    counter = 0
    for block in blocks:
        keystream = AES.new(key, AES.MODE_ECB).encrypt(nonce+p64(counter))
        ciphertext += xor(block, keystream)
        counter += 1
    return ciphertext

def ctrdecrypt(s,nonce,key):
    return ctrencrypt(s,nonce,key)

ciphertext = base64.b64decode("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==")
print(ctrdecrypt(ciphertext,bytes(8),b"YELLOW SUBMARINE"))
