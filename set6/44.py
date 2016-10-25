import binascii
import hashlib
import itertools

p = int('''800000000000000089e1855218a0e7dac38136ffafa72eda7
859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
1a584471bb1'''.replace('\n',''),16)

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

g = int('''5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
0f5b64c36b625a097f1651fe775323556fe00b3608c887892
878480e99041be601a62166ca6894bdd41a7054ec89f756ba
9fc95302291'''.replace('\n',''),16)

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

y = int('''2d026f4bf30195ede3a088da85e398ef869611d0f68f07
13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
2971c3de5084cce04a2e147821'''.replace('\n',''),16)

messages = []
mm = open('44.txt').read().strip().split('\n')
for i in range(0,len(mm),4):
    msg = mm[i].split(' ',1)[1]
    s = int(mm[i+1].split(' ',1)[1])
    r = int(mm[i+2].split(' ',1)[1])
    m = int(mm[i+3].split(' ',1)[1],16)
    messages.append((msg,s,r,m))

for i,j in itertools.combinations(messages,2):
    if i[2] == j[2]:
        m1, m2 = i[3], j[3]
        s1, s2 = i[1], j[1]
        k = ((m1-m2) * invmod(s1-s2, q)) % q
        H, r, s = i[3], i[2], i[1]
        break

check = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

x = (invmod(r,q) * (s*k - H)) % q
assert hashlib.sha1(enc(int2bytes(x))).hexdigest() == check
print('x =',x)
