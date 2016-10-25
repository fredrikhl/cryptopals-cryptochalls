import base64
import binascii
import random
import os
import struct

# implementation from https://github.com/sfstpala/SlowSHA

class SHA1 (object):
    _h0, _h1, _h2, _h3, _h4, = (
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

    def __init__(self, message, magic=None, messagelength=None):
        if magic != None:
            self._h0, self._h1, self._h2, self._h3, self._h4 = magic
        if messagelength != None:
            length = bin(messagelength * 8)[2:].rjust(64, "0")
        else:
            length = bin(len(message) * 8)[2:].rjust(64, "0")
        while len(message) > 64:
            self._handle(''.join(bin(i)[2:].rjust(8, "0")
                for i in message[:64]))
            message = message[64:]
        message = ''.join(bin(i)[2:].rjust(8, "0") for i in message) + "1"
        message += "0" * ((448 - len(message) % 512) % 512) + length
        for i in range(len(message) // 512):
            self._handle(message[i * 512:i * 512 + 512])

    def _handle(self, chunk):

        lrot = lambda x, n: (x << n) | (x >> (32 - n))
        w = []

        for j in range(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in range(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in range(80):

            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6

            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff

    def _digest(self):
        return (self._h0, self._h1, self._h2, self._h3, self._h4)

    def hexdigest(self):
        return ''.join(hex(i)[2:].rjust(8, "0")
            for i in self._digest())

    def digest(self):
        hexdigest = self.hexdigest()
        return bytes(int(hexdigest[i * 2:i * 2 + 2], 16)
            for i in range(len(hexdigest) // 2))

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

SECRET = os.urandom(16)

def mac(s):
    return SHA1(SECRET+s).digest()

def sha1pad(s, secretlen):
    length = bin((secretlen+len(s)) * 8)[2:].rjust(64, "0")
    s = ''.join(bin(i)[2:].rjust(8, "0") for i in s) + "1"
    s += "0" * ((448 - (len(s)+secretlen*8) % 512) % 512) + length
    return bytes(int(s[i:i+8],2) for i in range(0,len(s),8))

s = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
m = mac(s)
append = b';admin=true'

for secretlen in range(32): # guess secret length
    magic = struct.unpack('>IIIII',m)
    s2 = sha1pad(s,secretlen) + append
    m2 = SHA1(append, magic=magic, messagelength=(len(s2)+secretlen)).digest()
    if m2 == mac(s2):
        print("Secret Length:",secretlen)
        print("Message:",s2)
        print("MAC:",m2)
        break
