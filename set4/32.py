import binascii
import requests
import sys

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

msg = 'foo'
sig = bytearray(20)

try:
    requests.get('http://localhost:9000',params={'file':msg, 'signature':e(sig)})
except requests.exceptions.ConnectionError:
    print("Is server running?")
    sys.exit(0)

NUMSAMPLES = 5

for i in range(20):
    print(i)
    maxtime = 0
    maxchar = 0
    for j in range(256):
        samples = []
        for k in range(NUMSAMPLES):
            sig[i] = j
            r = requests.get('http://localhost:9000',params={'file':msg, 'signature':e(sig)})
            samples.append(r.elapsed.total_seconds())
        medtime = sorted(samples)[NUMSAMPLES//2]
        print(i,hex(j),medtime,sorted(samples))
        if medtime > maxtime:
            maxtime = medtime
            maxchar = j
    sig[i] = maxchar

r = requests.get('http://localhost:9000',params={'file':msg, 'signature':e(sig)})
if r.status_code == 200:
    print("Found signature for",msg)
    print(e(sig))
