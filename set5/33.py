import random

p = int('''ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff'''.replace('\n',''),16)
g = 2

a = random.randrange(1,p-1)
A = pow(g,a,p)

b = random.randrange(1,p-1)
B = pow(g,b,p)

s1 = pow(B,a,p)
s2 = pow(A,b,p)

if s1 == s2:
    print("shared secret established!")
    print(s1)
