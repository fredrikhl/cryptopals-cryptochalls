import binascii
import string
from collections import defaultdict

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([a[i%len(a)]^b[i%len(b)] for i in range(max(len(a),len(b)))])

plain = b'''Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal'''

key = b'ICE'

print(e(xor(plain,key)))
