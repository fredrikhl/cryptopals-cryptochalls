import base64
import binascii
import random
import os
from Crypto.Cipher import AES

secret = base64.b64decode('''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK''')

key = os.urandom(16)

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def pad(s, blocksize=16):
    l = (blocksize - len(s) - 1) % blocksize + 1
    return s + bytes([l]*l)

def ecbencrypt(s,key):
    return AES.new(key, AES.MODE_ECB).encrypt(s)

def encryption_oracle(s):
    s = pad(s + secret)
    return ecbencrypt(s,key)

def detectecb(s):
    l = [s[i:i+16] for i in range(0,len(s),16)]
    for i in l:
        if l.count(i) > 1:
            return True
    return False

# Detect blocksize
l = len(encryption_oracle(b''))
x = 1
while len(encryption_oracle(b'A'*x)) == l:
    x += 1
BLOCKSIZE = len(encryption_oracle(b'A'*x)) - l

# Detect if ECB
assert detectecb(encryption_oracle(b'A'*BLOCKSIZE*2))

# Decrypt
s = encryption_oracle(b'')

prevplain = b'A'*BLOCKSIZE
plain = b''

for i in range(0,len(s),BLOCKSIZE):
    for j in range(BLOCKSIZE):
        prefix = b'A'*(BLOCKSIZE-1-j)
        ss = encryption_oracle(prefix)
        #print(prefix, plain, prevplain)
        for k in range(256):
            match = prevplain[j+1:] + plain[i:i+j] + bytes([k])
            if encryption_oracle(match)[:BLOCKSIZE] == ss[i:i+BLOCKSIZE]:
                plain += bytes([k])
                break
    prevplain = plain[-16:]
print(plain)
