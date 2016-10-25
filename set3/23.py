import time
import random

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

w = 32
u = 11
s, b = 7, 0x9D2C5680
t, c = 15, 0xEFC60000
l = 18

def undo_rightshift(y,s):
    for i in range(31-s,-1,-1):
        y ^= ((y & (1 << (i+s))) >> s)
    return y

def undo_leftshiftandmask(y,s,m):
    for i in range(s,32):
        y ^= ((y & (1 << (i-s))) << s) & m
    return y

def temper(y):
    y ^= (y >> u) # anding with d = 0xFFFFFFFF does nothing
    y ^= ((y << s) & b)
    y ^= ((y << t) & c)
    y ^= (y >> l)
    return y & ((1 << w) - 1)

def untemper(y):
    y = undo_rightshift(y,l)
    y = undo_leftshiftandmask(y,t,c)
    y = undo_leftshiftandmask(y,s,b)
    y = undo_rightshift(y,u)
    return y & ((1 << w) - 1)

assert untemper(temper(12345)) == 12345

mt = MersenneTwister(12345)
state = []
for i in range(624):
    state.append(untemper(mt.rand()))

mt2 = MersenneTwister(0)
mt2.state = state

for i in range(1000):
    assert mt.rand() == mt2.rand()

print("All good!")
