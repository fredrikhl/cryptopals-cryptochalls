import base64
import binascii
import random
import os
import struct
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
    s = '''SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
    Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
    RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
    RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
    SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
    T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
    T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
    UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
    QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
    T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
    VG8gcGxlYXNlIGEgY29tcGFuaW9u
    QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
    QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
    QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
    QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
    QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
    VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
    SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
    SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
    VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
    V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
    V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
    U2hlIHJvZGUgdG8gaGFycmllcnM/
    VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
    QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
    VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
    V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
    SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
    U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
    U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
    VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
    QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
    SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
    VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
    WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
    SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
    SW4gdGhlIGNhc3VhbCBjb21lZHk7
    SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
    VHJhbnNmb3JtZWQgdXR0ZXJseTo=
    QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='''.split()
    key = os.urandom(16)
    nonce = os.urandom(8)
    return [ctrencrypt(base64.b64decode(i),nonce,key) for i in s]

ciphertexts = gen_ciphertexts()
cl = max(len(i) for i in ciphertexts)
keystream = bytearray(cl)

while True:
    print(e(keystream))
    for i in ciphertexts:
        i = xor(i,bytes(keystream))
        print(e(i),i)
    index = int(input("Index: "))
    byte = eval(input("Key Byte: ")) # unsafe, but w/e, allows expressions
    keystream[index] = byte
