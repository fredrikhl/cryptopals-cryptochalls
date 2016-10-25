import base64
import binascii
import random
import sys
from Crypto.Util.number import getPrime

BITS = 256

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

def pkcs15pad(m):
    m2 = b'\x00\x02'
    for i in range(BITS//8 - 3 - len(m)):
        m2 += bytes([random.randrange(1,255)])
    m2 += b'\x00'
    m2 += m
    return m2

def int2bytes(i):
    b = []
    while i > 0:
        b.append(i % 0x100)
        i //= 0x100
    b += [0]*((BITS//8)-len(b))
    return bytes(b[::-1])

def bytes2int(b):
    return int(b2s(enc(b)),16)

def floordiv(a,b):
    return a//b

def ceildiv(a,b):
    return -(-a//b)

def encrypt(x, public):
    return pow(x, public[0], public[1])

def decrypt(x, private):
    return pow(x, private[0], private[1])

def genkey():
    p = q = n = phi = 0
    while phi % 65537 == 0:
        p = getPrime(BITS//2)
        q = getPrime(BITS//2)
        n = p*q
        phi = (p-1)*(q-1)
    e = 65537
    d = invmod(e, phi)
    return ((e, n),(d, n))

def padding_oracle(c, private):
    m = decrypt(c, private)
    m = int2bytes(m)
    return m[0] == 0 and m[1] == 2

public, private = genkey()
msg = pkcs15pad(b'kick it, CC')
c = encrypt(bytes2int(msg), public)
e,n = public

B = 2**(BITS-16)
s0 = n//(3*B)
while not padding_oracle((c*pow(s0,e,n))%n,private):
    s0 += 1
s = s0
print("initial s:",s)
prevs = 0
M = [(2*B,3*B-1)]
while True:
    a,b = M[0]
    if a == b:
        break
    rlo = ceildiv(a*s-3*B+1,n)
    rhi = floordiv(b*s-2*B,n)
    if rlo != rhi:
        print(rlo, rhi)
        print("More than 1 possible interval, try complete version of attack!")
        sys.exit(0)
    r = rlo
    M = [(max(a,ceildiv(2*B+r*n,s)),min(b,floordiv(3*B-1+r*n,s)))]
    print("interval:",M[0],M[0][1]-M[0][0])
    prevs = s
    r = ceildiv(2*(b*prevs - 2*B),n)
    while True:
        for s in range(ceildiv(2*B+r*n,b),floordiv(3*B+r*n,a)+1):
            if padding_oracle((c*pow(s,e,n))%n,private):
                print('new s:',s)
                print('new r:',r)
                break
        else:
            r += 1
            continue
        break
m = M[0][0]
print(int2bytes(m))
