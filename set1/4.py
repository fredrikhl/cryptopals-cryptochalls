import binascii
import string
from collections import defaultdict

def d(s):
    return binascii.unhexlify(s)

def e(s):
    return binascii.hexlify(s)

def xor(a,b):
    return bytes([i^j for i,j in zip(a,b)])

expected_freq = {' ': 15, 'E': 12.70, 'T': 9.06, 'A': 8.17, 'O': 7.51, 'I': 6.97, 'N': 6.75, 'S': 6.33, 'H': 6.09, 'R': 5.99, 'D': 4.25, 'L': 4.03, 'C': 2.78, 'U': 2.76, 'M': 2.41, 'W': 2.36, 'F': 2.23, 'G': 2.02, 'Y': 1.97, 'P': 1.93, 'B': 1.29, 'V': 0.98, 'K': 0.77, 'J': 0.15, 'X': 0.15, 'Q': 0.10, 'Z': 0.07}

def score(s):
    # chi-squared test
    # lower is better
    s = s.upper()
    chisquare = 0
    freq = defaultdict(int)
    for i in s:
        freq[i] += 1

    for l in expected_freq:
        observed = freq[l]/len(s)
        expected = expected_freq[l]
        chisquare += (observed - expected)**2/expected
    return chisquare

minminc = b''
minminp = b''
minmins = float('inf')

for line in open('4.txt'):
    ciphertext = d(line.strip())

    minp = ciphertext
    mins = float('inf')

    for i in range(256):
        key = bytes([i]*len(ciphertext))
        plain = xor(key,ciphertext)

        plainscore = score(plain.decode('latin'))
        if plainscore < mins:
            minp = plain
            mins = plainscore

    if mins < minmins:
        minminc = ciphertext
        minminp = minp
        minmins = mins
print(minminc)
print(minminp)
print(minmins)
