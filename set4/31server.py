import base64
import binascii
import random
import os
import struct
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

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

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

HMACKEY = os.urandom(64)

def hmac(s, key):
    if len(key) > 64:
        key = SHA1(key).digest()
    elif len(key) < 64:
        key += bytes(64-len(key))
    opad = xor(b'\x5c'*64,key)
    ipad = xor(b'\x36'*64,key)
    return SHA1(opad+SHA1(ipad+s).digest()).digest()

def insecure_compare(s1,s2):
    if len(s1) != len(s2):
        return False
    for i,j in zip(s1,s2):
        if i != j:
            return False
        time.sleep(0.05)
    return True

class HMACServer(BaseHTTPRequestHandler):
    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        if 'file' in params and 'signature' in params:
            msg = params['file'][0].encode('utf8')
            sig = params['signature'][0]
            print('real sig:',e(hmac(msg, HMACKEY)))
            if insecure_compare(hmac(msg, HMACKEY),d(sig)):
                self.send_response(200)
            else:
                self.send_response(500)
            self.send_header("Content-type", "text/html")
            self.end_headers()
        else:
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

print("Starting server at http://localhost:9000")
HTTPServer(("localhost", 9000), HMACServer).serve_forever()
