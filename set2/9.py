def pad(s, blocksize=16):
    l = (blocksize - len(s) - 1) % blocksize + 1
    return s + bytes([l]*l)

plaintext = b'YELLOW SUBMARINE'
print(pad(plaintext, 20))
