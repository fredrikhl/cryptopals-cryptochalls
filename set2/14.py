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
    s = os.urandom(random.randrange(1,15)) + s
    s = pad(s + secret)
    return ecbencrypt(s,key)

def detectecb(s):
    l = [s[i:i+16] for i in range(0,len(s),16)]
    for i in l:
        if l.count(i) > 1:
            return True
    return False

def getrepeatedblock(s):
    assert detectecb(s)
    l = [s[i:i+16] for i in range(0,len(s),16)]
    for i in l:
        if l.count(i) > 1:
            return i

# Detect blocksize
l = len(encryption_oracle(b''))
x = 1
l2 = l
while l2 == l:
    x += 1
    l2 = len(encryption_oracle(b'A'*x))
BLOCKSIZE = abs(l2 - l)
print(BLOCKSIZE)
assert BLOCKSIZE == 16

# Detect if ECB
assert detectecb(encryption_oracle(b'A'*BLOCKSIZE*3))

ablock = getrepeatedblock(encryption_oracle(b'A'*BLOCKSIZE*3))
bblock = getrepeatedblock(encryption_oracle(b'B'*BLOCKSIZE*3))

# Decrypt
def constant_encryption_oracle(s):
    prefix = b'A'*(BLOCKSIZE-3) + b'A'*BLOCKSIZE + b'B'*BLOCKSIZE + s
    ss = b''
    while ablock not in ss or bblock not in ss:        
        ss = encryption_oracle(prefix)
    return ss[BLOCKSIZE*3:]
    
s = constant_encryption_oracle(b'')

prevplain = b'A'*BLOCKSIZE
plain = b''

for i in range(0,len(s),BLOCKSIZE):
    for j in range(BLOCKSIZE):
        prefix = b'A'*(BLOCKSIZE-1-j)      
        ss = constant_encryption_oracle(prefix)
        #print(prefix, plain, prevplain)
        for k in range(256):
            match = prevplain[j+1:] + plain[i:i+j] + bytes([k])
            if constant_encryption_oracle(match)[:BLOCKSIZE] == ss[i:i+BLOCKSIZE]:
                plain += bytes([k])
                break
    prevplain = plain[-16:]
print(plain)
