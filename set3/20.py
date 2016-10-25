import base64
import binascii
import random
import os
import string
import struct
from collections import defaultdict
from Crypto.Cipher import AES

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

def p64(i):
    return struct.pack("<q",i)

def ctrencrypt(s,nonce,key):
    blocks = [s[i:i+16] for i in range(0,len(s),16)]
    ciphertext = b''
    counter = 0
    for block in blocks:
        keystream = AES.new(key, AES.MODE_ECB).encrypt(nonce+p64(counter))
        ciphertext += xor(block, keystream)
        counter += 1
    return ciphertext

def ctrdecrypt(s,nonce,key):
    return ctrencrypt(s,nonce,key)

def gen_ciphertexts():
    s = open("20.txt").read().split()
    key = os.urandom(16)
    nonce = os.urandom(8)
    return [ctrencrypt(base64.b64decode(i),nonce,key) for i in s]

expected_freq = {' ': 15, 'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}

def score(s):
    # chi-squared test
    # lower is better
    s = s.upper()
    chisquare = 0
    freq = defaultdict(int)
    for i in s:
        freq[i] += 1

    for l in expected_freq:
        observed = freq[l]/len(s)
        expected = expected_freq[l]
        chisquare += (observed - expected)**2/expected
    return chisquare

def breaksinglexor(ciphertext):
    minp = ciphertext
    mins = float('inf')

    for i in range(256):
        key = bytes([i]*len(ciphertext))
        plain = xor(key,ciphertext)
        if any(chr(i) not in string.printable for i in plain):
            continue
        plainscore = score(plain.decode('latin'))
        if plainscore < mins:
            minp = plain
            mins = plainscore

    return minp

def breakrepeatedkeyxor(ciphertext, keysize):
    final = [b'']*len(ciphertext)
    for i in range(keysize):
        final[i::keysize] = breaksinglexor(ciphertext[i::keysize])
    return bytes(final)

ciphertexts = gen_ciphertexts()
cl = min(len(i) for i in ciphertexts)
concatciphertexts = b''.join(i[:cl] for i in ciphertexts)
plain = breakrepeatedkeyxor(concatciphertexts, cl)
for i in range(0,len(plain),cl):
    print(plain[i:i+cl])
