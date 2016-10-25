import binascii
import hashlib
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

def encrypt(x, public):
    return pow(x, public[0], public[1])

def decrypt(x, private):
    return pow(x, private[0], private[1])

def sign(msg, private):
    h = hashlib.sha256(msg).digest()
    asn1 = dec('3031300d060960864801650304020105000420')
    sig = b'\x00\x01' + b'\xff'*(256-3-len(asn1)-len(h)) + b'\x00' + asn1 + h
    sig = bytes2int(sig)
    return pow(sig, private[0], private[1])

def verify(sig, msg, public):
    h = hashlib.sha256(msg).digest()
    sig = pow(sig, public[0], public[1])
    sig = int2bytes(sig, 256)
    if sig[:2] != b'\x00\x01':
        return False
    i = sig[2:].index(b'\x00')
    if i == -1 or any(j != 0xff for j in sig[2:i+2]):
        return False
    asn1 = dec('3031300d060960864801650304020105000420')
    if len(sig[i+3:i+3+len(asn1+h)]) != len(asn1+h) or sig[i+3:i+3+len(asn1+h)] != asn1+h:
        return False
    return True

def genkey():
    p = q = n = phi = 0
    while phi % 3 == 0:
        p = getPrime(1024)
        q = getPrime(1024)
        n = p*q
        phi = (p-1)*(q-1)
    e = 3
    d = invmod(e, phi)
    return ((e, n),(d, n))

public, private = genkey()
e,n = public
msg = b'hi mom'

h = hashlib.sha256(msg).digest()
asn1 = dec('3031300d060960864801650304020105000420')
fakesig = b'\x00\x01' + b'\xff'*(256-3-len(asn1)-len(h)-200) + b'\x00' + asn1 + h + b'\x00'*200
fakesig = cbrt(bytes2int(fakesig))
print(verify(fakesig, msg, public))
