import socket
import json
from rsa_util import rsa_encrypt

# PKA private key
pka_private_key = (2753, 3233)

# Public keys for server2 (user1) and server1 (user2)
server2_public_key = (7, 143)   # Public key for user1
server1_public_key = (67, 187)   # Correct public key for user2

def pka_server():
    server = socket.socket()
    server.bind(('localhost', 5000))
    server.listen(5)
    print("PKA Server is running on localhost:5000...")
    while True:
        conn, _ = server.accept()
        request = conn.recv(1024).decode()
        print(f"Request received for: {request}")
        
        if request == 'user1':
            encrypted_keys = {
                "e": rsa_encrypt(server1_public_key[0], *pka_private_key),  # Encrypt server1's e
                "n": rsa_encrypt(server1_public_key[1], *pka_private_key)   # Encrypt server1's n
            }
        elif request == 'user2':
            encrypted_keys = {
                "e": rsa_encrypt(server2_public_key[0], *pka_private_key),  # Encrypt server2's e
                "n": rsa_encrypt(server2_public_key[1], *pka_private_key)   # Encrypt server2's n
            }
        else:
            encrypted_keys = {"error": "Invalid user request."}

        conn.send(json.dumps(encrypted_keys).encode())
        conn.close()

if __name__ == '__main__':
    pka_server()
