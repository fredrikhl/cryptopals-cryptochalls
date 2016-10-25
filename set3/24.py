import time
import random
import os
import struct

class MersenneTwister:
    # constants for MT19937
    w, n, m, r = 32, 624, 397, 31
    a = 0x9908B0DF
    u, d = 11, 0xFFFFFFFF
    s, b = 7, 0x9D2C5680
    t, c = 15, 0xEFC60000
    l = 18
    f = 1812433253

    def __init__(self, seed):
        self.state = [0]*self.n
        self.index = self.n
        self.wmask = ((1 << self.w) - 1)
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (~self.lower_mask) & self.wmask
        self.seed(seed)

    def seed(self, seed):
        self.state[0] = seed
        for i in range(1,self.n):
            self.state[i] = ((self.f * (self.state[i-1] ^
                            (self.state[i-1] >> (self.w-2))) + i)
                            & self.wmask)

    def rand(self):
        if self.index >= self.n:
            self.twist()
        y = self.state[self.index]

        y ^= ((y >> self.u) & self.d)
        y ^= ((y << self.s) & self.b)
        y ^= ((y << self.t) & self.c)
        y ^= (y >> self.l)

        self.index += 1

        return y & self.wmask

    def twist(self):
        for i in range(self.n):
            x = ((self.state[i] & self.upper_mask) +
                (self.state[(i+1) % self.n] & self.lower_mask))
            xA = x >> 1
            if x % 2 != 0:
                xA = xA ^ self.a
            self.state[i] = self.state[(i+self.m) % self.n] ^ xA
        self.index = 0

KEY = random.randrange(0,0xFFFF)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

def mtencrypt(s,key):
    ciphertext = b''
    blocks = [s[i:i+4] for i in range(0,len(s),4)]
    mt = MersenneTwister(key)
    for block in blocks:
        ciphertext += xor(block, struct.pack('<I',mt.rand()))
    return ciphertext

def mtdecrypt(s,key):
    return mtencrypt(s,key)

def encryption_oracle(s):
    s = os.urandom(random.randrange(1,8)) + s
    return mtencrypt(s,KEY)

def gentoken():
    return mtencrypt(b'AAAABBBBCCCCDDDD',int(time.time()))

def checktoken(token):
    return mtdecrypt(token,int(time.time())) == b'AAAABBBBCCCCDDDD'

s = encryption_oracle(b'A'*20)
c = xor(b'AAAAAAAA',s[8:16])
mtvals = struct.unpack('<II',c)

for i in range(0x10000):
    if i % 0x100 == 0:
        print(hex(i))
    mt = MersenneTwister(i)
    for j in range(2):
        mt.rand()
    test = []
    for j in range(2):
        test.append(mt.rand())
    test = tuple(test)
    if mtvals == test:
        print('found key:',i)
        break
