import binascii
import os
import random
import socket
import sys
import hashlib
from Crypto.Cipher import AES

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

def pad(s, blocksize=16):
    l = (blocksize - len(s) - 1) % blocksize + 1
    return s + bytes([l]*l)

def unpad(s):
    l = s[-1]
    if any(i != l for i in s[-l:]):
        raise ValueError("Invalid padding!")
    return s[:-l]

def int2bytes(i):
    b = []
    while i > 0:
        b.append(i % 0x100)
        i //= 0x100
    return bytes(b[::-1])

def cbcencrypt(s,iv,key):
    blocks = [s[i:i+16] for i in range(0,len(s),16)]
    prevblock = iv
    ciphertext = b''
    for block in blocks:
        block = xor(prevblock, block)
        block = AES.new(key, AES.MODE_ECB).encrypt(block)
        prevblock = block
        ciphertext += block
    return ciphertext

def cbcdecrypt(s,iv,key):
    blocks = [s[i:i+16] for i in range(0,len(s),16)]
    prevblock = iv
    plaintext = b''
    for block in blocks:
        block2 = AES.new(key, AES.MODE_ECB).decrypt(block)
        block2 = xor(prevblock, block2)
        prevblock = block
        plaintext += block2
    return plaintext

def s2b(s):
    return s.encode('utf8')

def b2s(b):
    return b.decode('utf8')

def readline(sock):
    s = b''
    while not s.endswith(b'\n'):
        s += sock.recv(1)
    return s[:-1]

def writeline(sock, line):
    sock.send(line+b'\n')

asoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
asoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
asoc.bind(('localhost',9001))
asoc.listen(1)
conn, addr = asoc.accept()

p = int(b2s(readline(conn)))
g = int(b2s(readline(conn)))
A = int(b2s(readline(conn)))
b = random.randrange(1,p-1)
B = pow(g,b,p)
writeline(conn,s2b(str(B)))
s = pow(A,b,p)

key = hashlib.sha1(int2bytes(s)).digest()[:16]
recvcipher = d(readline(conn))
iv, ciphertext = recvcipher[:16], recvcipher[16:]

plaintext = unpad(cbcdecrypt(ciphertext, iv, key))
print("A's message:",plaintext)

iv = os.urandom(16)
ciphertext = cbcencrypt(pad(plaintext), iv, key)

writeline(conn, e(iv+ciphertext))
