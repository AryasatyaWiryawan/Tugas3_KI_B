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
    # Encrypt each integer in the message
    if isinstance(message, str):
        return [pow(ord(char), key, n) for char in message]
    return pow(message, key, n)  # Handle integers

def rsa_decrypt(encrypted_message, key, n):
    # Decrypt each integer to characters
    if isinstance(encrypted_message, list):
        return ''.join([chr(pow(char, key, n)) for char in encrypted_message])
    return pow(encrypted_message, key, n)  # Handle integers
