import hashlib
import random
from sympy import isprime, nextprime, primerange, divisors
def find_large_safe_prime(bits=256):
    """生成一个指定比特数的安全素数 p，使得 p = 2q + 1，其中 q 也是素数"""
    while True:
        q = nextprime(random.getrandbits(bits - 1))
        p = 2 * q + 1
        if isprime(p):
            return p, q

def find_generator(p, q):
    """在有限域 Z_p 中找到一个生成元 g"""
    for g in range(2, p):
        # 检查 g 是否满足生成元的条件，即 g^q ≠ 1 (mod p)
        if pow(g, q, p) != 1 and pow(g, 2, p) != 1:
            return g
    return None

def gen_p_q_g():
    p, q = find_large_safe_prime(256)
    g = find_generator(p, q)
    return p, q, g

def gen_x_h(g, q):
    x = random.randint(1, q - 1) # x是签名者的私钥
    h = pow(g, x, q) # y=pow(g, x, q)是签名者的公钥
    return x, h