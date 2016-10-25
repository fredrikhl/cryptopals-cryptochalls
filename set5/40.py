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

def cbrt(x):
    low = 0
    high = x
    while low < high:
        mid = (low+high) // 2
        if mid**3 < x:
            low = mid+1
        elif mid**3 > x:
            high = mid
        else:
            return mid
    return low

def d(s):
    return binascii.unhexlify(s)

def e(s):
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
    return int(b2s(e(b)),16)

def encrypt(x, public):
    return pow(x, public[0], public[1])

def decrypt(x, private):
    return pow(x, private[0], private[1])

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

public0, private0 = genkey()
public1, private1 = genkey()
public2, private2 = genkey()

msg = b'This is a very good message.'

c0 = encrypt(bytes2int(msg), public0)
c1 = encrypt(bytes2int(msg), public1)
c2 = encrypt(bytes2int(msg), public2)

n0 = public0[1]
n1 = public1[1]
n2 = public2[1]

c = ((c0 * n1*n2 * invmod(n1*n2,n0))+
     (c1 * n0*n2 * invmod(n0*n2,n1))+
     (c2 * n0*n1 * invmod(n0*n1,n2))) % (n0*n1*n2)

print(int2bytes(cbrt(c)))
