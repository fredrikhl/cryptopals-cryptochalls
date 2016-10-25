import binascii

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

print(e(xor(d('1c0111001f010100061a024b53535009181c'),
            d('686974207468652062756c6c277320657965'))))
