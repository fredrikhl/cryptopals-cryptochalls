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

for i in range(20):
    print(i)
    for j in range(256):
        sig[i] = j
        r = requests.get('http://localhost:9000',params={'file':msg, 'signature':e(sig)})
        time = r.elapsed.total_seconds()
        print(i,j,time)
        if time > (i+1)*0.05 or r.status_code == 200:
            break

r = requests.get('http://localhost:9000',params={'file':msg, 'signature':e(sig)})
if r.status_code == 200:
    print("Found signature for",msg)
    print(e(sig))
