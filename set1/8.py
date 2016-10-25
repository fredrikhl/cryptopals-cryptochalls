import binascii
from collections import defaultdict

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

for line in open("8.txt"):
    line = d(line.strip())
    l = [line[i:i+16] for i in range(0,len(line),16)]
    for i in l:
        if l.count(i) > 1:
            print(e(line))
            break
