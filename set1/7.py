import base64
from Crypto.Cipher import AES

ciphertext = base64.b64decode(open('7.txt').read())
key = b'YELLOW SUBMARINE'

print(AES.new(key, AES.MODE_ECB).decrypt(ciphertext).decode('utf8'))
