import binascii
import os
import random
import socket
import sys
import hashlib
from Crypto.Cipher import AES

N = int('''ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'''.replace('\n',''),16)
g = 2
email = b'example@example.com'
password = b'aardvark'

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def s2b(s):
    return s.encode('utf8')

def b2s(b):
    return b.decode('utf8')

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

def bytes2int(b):
    return int(b2s(e(b)),16)

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

def readline(sock):
    s = b''
    while not s.endswith(b'\n'):
        s += sock.recv(1)
    return s[:-1]

def writeline(sock, line):
    sock.send(line+b'\n')

def hmac(s, key):
    if len(key) > 64:
        key = hashlib.sha256(key).digest()
    elif len(key) < 64:
        key += bytes(64-len(key))
    opad = xor(b'\x5c'*64,key)
    ipad = xor(b'\x36'*64,key)
    return hashlib.sha256(opad+hashlib.sha256(ipad+s).digest()).digest()

salt = random.randrange(0,0xFFFFFFFFFFFFFFFF)
xH = hashlib.sha256(int2bytes(salt) + password).digest()
x = bytes2int(xH)
v = pow(g,x,N)

csoc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
csoc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
csoc.bind(('localhost',9001))
csoc.listen(1)
conn, addr = csoc.accept()

I = b2s(readline(conn))
A = int(b2s(readline(conn)))
writeline(conn,s2b(str(salt)))
b = random.randrange(1,N-1)
B = pow(g,b,N)
writeline(conn,s2b(str(B)))

u = random.randrange(0,2**128-1)
writeline(conn,s2b(str(u)))
S = pow((A * pow(v,u,N)) % N,b,N)
K = hashlib.sha256(int2bytes(S)).digest()

Khmac = hmac(int2bytes(salt), K)
Khmac2 = d(readline(conn))

if Khmac == Khmac2:
    writeline(conn,b'OK')
else:
    writeline(conn,b'NO')

conn.close()
csoc.close()
