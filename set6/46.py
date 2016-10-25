import base64
import binascii
from fractions import Fraction
from Crypto.Util.number import getPrime

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

def int2bytes(i):
    b = []
    while i > 0:
        b.append(i % 0x100)
        i //= 0x100
    return bytes(b[::-1])

def bytes2int(b):
    return int(b2s(enc(b)),16)

def encrypt(x, public):
    return pow(x, public[0], public[1])

def decrypt(x, private):
    return pow(x, private[0], private[1])

def genkey():
    p = q = n = phi = 0
    while phi % 65537 == 0:
        p = getPrime(512)
        q = getPrime(512)
        n = p*q
        phi = (p-1)*(q-1)
    e = 65537
    d = invmod(e, phi)
    return ((e, n),(d, n))

def parity_oracle(c, private):
    m = decrypt(c, private)
    return m%2 == 0

public, private = genkey()
msg = base64.b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
c = encrypt(bytes2int(msg), public)
e,n = public

lo = Fraction(0)
hi = Fraction(n)

c2 = c

while hi-lo >= 1:
    c2 = (c2 * pow(2,e,n)) % n
    mid = (lo+hi)/2
    if parity_oracle(c2, private):
        hi = mid
    else:
        lo = mid
    print(int2bytes(int(mid)))
hi = int(hi)
print(int2bytes(int(hi)))
