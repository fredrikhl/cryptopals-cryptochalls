import binascii
import hashlib
import itertools
import random

p = int('''800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1'''.replace('\n',''),16)

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

def egcd(a, b):
    s = 0
    t = 1
    r = b
    olds = 1
    oldt = 0
    oldr = a
    while r != 0:
        q = oldr // r
        oldr, r = r, oldr - q*r
        olds, s = s, olds - q*s
        oldt, t = t, oldt - q*t
    return (olds, oldt, oldr)

def invmod(a, n):
    return egcd(a, n)[0] % n

def dec(s):
    return binascii.unhexlify(s)

def enc(s):
    return binascii.hexlify(s)

def s2b(s):
    return s.encode('utf8')

def b2s(b):
    return b.decode('utf8')

def int2bytes(i, length=0):
    b = []
    while i > 0:
        b.append(i % 0x100)
        i //= 0x100
    if length > 0:
        b += [0]*(length-len(b))
    return bytes(b[::-1])

def bytes2int(b):
    return int(b2s(enc(b)),16)

def genkey():
    x = random.randrange(1,q-1)
    y = pow(g,x,p)
    return (y, x)

def sign(msg, private):
    H = bytes2int(hashlib.sha1(msg).digest())
    r = s = 0
    while r == 0 or s == 0:
        k = random.randrange(1,q-1)
        r = pow(g,k,p) % q
        s = (invmod(k,q) * (H + private*r)) % q
    return (r,s)

def verify(msg, sig, public):
    H = bytes2int(hashlib.sha1(msg).digest())
    r,s = sig
    if not 0 < r < q or not 0 < s < q:
        return False
    w = invmod(s,q)
    u1 = (H*w) % q
    u2 = (r*w) % q
    v = ((pow(g,u1,p) * pow(public,u2,p)) % p) % q
    return v == r

g = p+1

public, private = genkey()
fakesig = ((public % p) % q, (public % p) % q)
print(verify(b'Hello, world', fakesig, public))
print(verify(b'Goodbye, world', fakesig, public))
