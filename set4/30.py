import base64
import binascii
import random
import os
import struct

# implementation from http://acooke.org/cute/PurePython0.html

from itertools import zip_longest

def grouped(iterable, n, fillvalue=None):
	'''group in to chunks - http://stackoverflow.com/a/434411/181772'''
	args = [iter(iterable)] * n
	return zip_longest(*args, fillvalue=fillvalue)

def little_endian_bytes(words, n):
    '''convert n-byte words to bytes (little endian)'''
    for word in words:
        for _ in range(n):
            yield word & 0xff
            word >>= 8

def big_endian_bytes(words, n):
    '''convert n-byte words to bytes (big endian)'''
    for word in words:
        yield from reversed(list(little_endian_bytes([word], n)))

def big_endian_words(b, n):
    '''convert bytes into n-byte words (big endian)'''
    for g in grouped(b, n):
        w = 0
        for b in g:
            w = w << 8 | b
        yield w

def little_endian_words(b, n):
    '''convert bytes into n-byte words (little endian)'''
    for g in grouped(b, n):
        yield from big_endian_words(reversed(g), n)

# http://www.oocities.org/rozmanov/python/md4.html
# Copyright (C) 2001-2002  Dmitry Rozmanov (LGPL)
# modified

def left_rotate(n, b):
    return ((n << b) | ((n & 0xffffffff) >> (32 - b))) & 0xffffffff

def md_pad_64(message, length_to_bytes, fake_byte_len=None):
    original_byte_len = len(message)
    message += b'\x80'
    message += b'\x00' * ((56 - (original_byte_len + 1) % 64) % 64)
    original_bit_len = (fake_byte_len if fake_byte_len else original_byte_len) * 8
    message += bytes(length_to_bytes(original_bit_len))
    return message

def make_md_hash_64(compress, state_to_hash, length_to_bytes):
    def md_hash(message, fake_byte_len=None, state=None):
        message = md_pad_64(message, length_to_bytes, fake_byte_len=fake_byte_len)
        for i in range(0, len(message), 64):
            state = compress(message[i:i+64], state)
        return state_to_hash(state)
    return md_hash

def f(x, y, z): return x & y | ~x & z
def g(x, y, z): return x & y | x & z | y & z
def h(x, y, z): return x ^ y ^ z

def f1(a, b, c, d, k, s, X): return left_rotate(a + f(b, c, d) + X[k], s)
def f2(a, b, c, d, k, s, X): return left_rotate(a + g(b, c, d) + X[k] + 0x5a827999, s)
def f3(a, b, c, d, k, s, X): return left_rotate(a + h(b, c, d) + X[k] + 0x6ed9eba1, s)

def md4_compress(block, state=None):

    if not state: state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]
    a, b, c, d = h0, h1, h2, h3 = state

    x = list(little_endian_words(block, 4))

    a = f1(a,b,c,d, 0, 3, x)
    d = f1(d,a,b,c, 1, 7, x)
    c = f1(c,d,a,b, 2,11, x)
    b = f1(b,c,d,a, 3,19, x)
    a = f1(a,b,c,d, 4, 3, x)
    d = f1(d,a,b,c, 5, 7, x)
    c = f1(c,d,a,b, 6,11, x)
    b = f1(b,c,d,a, 7,19, x)
    a = f1(a,b,c,d, 8, 3, x)
    d = f1(d,a,b,c, 9, 7, x)
    c = f1(c,d,a,b,10,11, x)
    b = f1(b,c,d,a,11,19, x)
    a = f1(a,b,c,d,12, 3, x)
    d = f1(d,a,b,c,13, 7, x)
    c = f1(c,d,a,b,14,11, x)
    b = f1(b,c,d,a,15,19, x)

    a = f2(a,b,c,d, 0, 3, x)
    d = f2(d,a,b,c, 4, 5, x)
    c = f2(c,d,a,b, 8, 9, x)
    b = f2(b,c,d,a,12,13, x)
    a = f2(a,b,c,d, 1, 3, x)
    d = f2(d,a,b,c, 5, 5, x)
    c = f2(c,d,a,b, 9, 9, x)
    b = f2(b,c,d,a,13,13, x)
    a = f2(a,b,c,d, 2, 3, x)
    d = f2(d,a,b,c, 6, 5, x)
    c = f2(c,d,a,b,10, 9, x)
    b = f2(b,c,d,a,14,13, x)
    a = f2(a,b,c,d, 3, 3, x)
    d = f2(d,a,b,c, 7, 5, x)
    c = f2(c,d,a,b,11, 9, x)
    b = f2(b,c,d,a,15,13, x)

    a = f3(a,b,c,d, 0, 3, x)
    d = f3(d,a,b,c, 8, 9, x)
    c = f3(c,d,a,b, 4,11, x)
    b = f3(b,c,d,a,12,15, x)
    a = f3(a,b,c,d, 2, 3, x)
    d = f3(d,a,b,c,10, 9, x)
    c = f3(c,d,a,b, 6,11, x)
    b = f3(b,c,d,a,14,15, x)
    a = f3(a,b,c,d, 1, 3, x)
    d = f3(d,a,b,c, 9, 9, x)
    c = f3(c,d,a,b, 5,11, x)
    b = f3(b,c,d,a,13,15, x)
    a = f3(a,b,c,d, 3, 3, x)
    d = f3(d,a,b,c,11, 9, x)
    c = f3(c,d,a,b, 7,11, x)
    b = f3(b,c,d,a,15,15, x)

    return [(h0 + a) & 0xffffffff, (h1 + b) & 0xffffffff, (h2 + c) & 0xffffffff, (h3 + d) & 0xffffffff]

MD4 = make_md_hash_64(md4_compress, lambda state: little_endian_bytes(state, 4), lambda length: little_endian_bytes([length], 8))

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

SECRET = os.urandom(16)

def mac(s):
    return bytes(MD4(SECRET+s))

def md4pad(s, secretlen):
    bitlength = (secretlen+len(s))*8
    s = ''.join(bin(i)[2:].rjust(8, "0") for i in s) + "1"
    s += "0" * ((448 - (len(s)+secretlen*8) % 512) % 512)
    return bytes(int(s[i:i+8],2) for i in range(0,len(s),8)) + struct.pack("<Q",bitlength)

s = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
m = mac(s)
append = b';admin=true'

for secretlen in range(32): # guess secret length
    state = struct.unpack('<IIII',m)
    s2 = md4pad(s,secretlen) + append
    m2 = bytes(MD4(append, state=state, fake_byte_len=(len(s2)+secretlen)))
    if m2 == mac(s2):
        print("Secret Length:",secretlen)
        print("Message:",s2)
        print("MAC:",m2)
        break
