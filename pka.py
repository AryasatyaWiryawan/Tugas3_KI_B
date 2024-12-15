# pka.py
import socket
import json
from rsa_util import rsa_encrypt

pka_public_key = (17, 3233)
pka_private_key = (2753, 3233)

alice_public_key = (7, 143)
bob_public_key = (11, 187)

def pka_server():
    server = socket.socket()
    server.bind(('localhost', 5000))
    server.listen(5)
    while True:
        conn, _ = server.accept()
        request = conn.recv(1024).decode()
        if request == 'user1':
            encrypted_keys = {
                "e": rsa_encrypt(str(bob_public_key[0]), *pka_private_key),
                "n": rsa_encrypt(str(bob_public_key[1]), *pka_private_key)
            }
        elif request == 'user2':
            encrypted_keys = {
                "e": rsa_encrypt(str(alice_public_key[0]), *pka_private_key),
                "n": rsa_encrypt(str(alice_public_key[1]), *pka_private_key)
            }
        conn.send(json.dumps(encrypted_keys).encode())
        conn.close()

if __name__ == '__main__':
    pka_server()
