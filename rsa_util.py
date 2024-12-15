# rsa_util.py
from math import gcd

def generate_rsa_keys(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 3
    while gcd(e, phi) != 1:
        e += 2
    d = pow(e, -1, phi)
    return (e, n), (d, n)

def rsa_encrypt(message, key, n):
    return [pow(ord(char), key, n) for char in message]

def rsa_decrypt(encrypted_message, key, n):
    return ''.join([chr(pow(char, key, n)) for char in encrypted_message])
