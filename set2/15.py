import base64
import binascii
import random
import os
from collections import OrderedDict

from Crypto.Cipher import AES

KEY = os.urandom(16)

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def pad(s, blocksize=16):
    l = (blocksize - len(s) - 1) % blocksize + 1
    return s + bytes([l]*l)

def unpad(s):
    l = s[-1]
    if any(i != l for i in s[-l:]):
        raise ValueError("Invalid padding!")
    return s[:-l]

print(unpad(b'ICE ICE BABY\x01\x02\x03\x04'))
