import binascii
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

def sign(x, private, blacklist=[]):
    if x in blacklist:
        raise ValueError("This message not allowed!")
    return decrypt(x, private)

def genkey():
    p = q = n = phi = 0
    while phi % 3 == 0:
        p = getPrime(512)
        q = getPrime(512)
        n = p*q
        phi = (p-1)*(q-1)
    e = 3
    d = invmod(e, phi)
    return ((e, n),(d, n))

public, private = genkey()
e,n = public
msg = b'This is a very very very very secret message. Shh!'

c = encrypt(bytes2int(msg), public)
blacklist = [c]
s = 2
c2 = (pow(s,e,n) * c) % n
p2 = sign(c2, private, blacklist)
p = (p2 * invmod(s,n)) % n

print(int2bytes(p))
