import base64
import binascii
import random
import os
import string
import struct
from collections import defaultdict
from Crypto.Cipher import AES

KEY = os.urandom(16)
NONCE = os.urandom(8)

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

def p64(i):
    return struct.pack("<q",i)

def ecbdecrypt(s,key):
    return AES.new(key, AES.MODE_ECB).decrypt(s)

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

def edit(ciphertext, key, offset, newtext):
    plaintext = ctrdecrypt(ciphertext,NONCE,key)
    plaintext = plaintext[:offset] + newtext + plaintext[offset+len(newtext):]
    return ctrencrypt(plaintext,NONCE,key)

def edit_exposed(ciphertext, offset, newtext):
    return edit(ciphertext, KEY, offset, newtext)

ciphertext = base64.b64decode(open("25.txt").read())
ciphertext = ecbdecrypt(ciphertext,b'YELLOW SUBMARINE')
ciphertext = ctrencrypt(ciphertext,NONCE,KEY)

ciphertext2 = ciphertext
plaintext = b''

for i in range(len(ciphertext)):
    for j in range(256):
        ciphertext2 = edit_exposed(ciphertext2, i, bytes([j]))
        if ciphertext2 == ciphertext:
            plaintext += bytes([j])
            print(plaintext)
            break

print(plaintext)
