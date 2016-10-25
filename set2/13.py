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
    return s[:-l]

def ecbencrypt(s,key):
    return AES.new(key, AES.MODE_ECB).encrypt(s)

def ecbdecrypt(s,key):
    return AES.new(key, AES.MODE_ECB).decrypt(s)

def parse(s):
    l = s.split(b'&')
    d = OrderedDict()
    for i in l:
        key, val = i.split(b'=')
        if key in d:
            print("Warning:",key,"already in object")
        d[key] = val
    return d

def encode(d):
    return(b'&'.join(i+b'='+d[i] for i in d))

def profile_for(email):
    email = email.replace(b'&',b'').replace(b'=',b'')
    d = OrderedDict()
    d[b'email'] = email
    d[b'uid'] = b'10'
    d[b'role'] = b'user'
    return d

def encrypt(d):
    return ecbencrypt(pad(encode(d)),KEY)

def decrypt(s):
    return parse(unpad(ecbdecrypt(s,KEY)))

def oracle(email):
    return encrypt(profile_for(email))

adminblock = oracle(b'A'*10+b'admin'+b'\x0b'*11)[16:32]
print(adminblock)

print(decrypt(oracle(b'A'*13)[:-16]+adminblock))
