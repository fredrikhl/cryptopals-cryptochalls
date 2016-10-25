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

if len(sys.argv) < 2 or sys.argv[1] not in ['1','2','3']:
    print("Usage:",sys.argv[0],"{1,2,3}")
    sys.exit(0)
attacktype = sys.argv[1]


bsoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bsoc.connect(('localhost',9001))

asoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
asoc.bind(('localhost',9002))
asoc.listen(1)
conn, addr = asoc.accept()

p = int(b2s(readline(conn)))
g = int(b2s(readline(conn)))

if attacktype == '1':
    print("g = 1")
    g = 1
elif attacktype == '2':
    print("g = p")
    g = p
elif attacktype == '3':
    print("g = p-1")
    g = p-1

writeline(bsoc,s2b(str(p)))
writeline(bsoc,s2b(str(g)))
p = int(b2s(readline(bsoc)))
g = int(b2s(readline(bsoc)))
writeline(conn,s2b(str(p)))
writeline(conn,s2b(str(g)))
A = int(b2s(readline(conn)))
writeline(bsoc,s2b(str(A)))
B = int(b2s(readline(bsoc)))
writeline(conn,s2b(str(B)))

if attacktype == '1':
    s = 1
elif attacktype == '2':
    s = 0
elif attacktype == '3':
    if A == p-1 and B == p-1: # a and b are both odd
        s = p-1
    else:
        s = 1

key = hashlib.sha1(int2bytes(s)).digest()[:16]
recvcipher = d(readline(conn))
writeline(bsoc,e(recvcipher))
iv, ciphertext = recvcipher[:16], recvcipher[16:]
plaintext = unpad(cbcdecrypt(ciphertext, iv, key))
print("A's message:",plaintext)

recvcipher = d(readline(bsoc))
writeline(conn,e(recvcipher))
iv, ciphertext = recvcipher[:16], recvcipher[16:]
plaintext = unpad(cbcdecrypt(ciphertext, iv, key))
print("B's message:",plaintext)

asoc.close()
bsoc.close()
