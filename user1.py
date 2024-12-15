# user1.py
import socket
import json
from rsa_util import rsa_encrypt, rsa_decrypt
from des_util import des_encrypt

# Private key of user1
private_key_user1 = (7, 143)

def user1():
    # Get public key of user2 from PKA
    pka_socket = socket.socket()
    pka_socket.connect(('localhost', 5000))
    pka_socket.send(b'user1')
    response = json.loads(pka_socket.recv(1024).decode())
    pka_socket.close()

    # Decrypt the received keys using user1's private key
    e_user2 = int(rsa_decrypt(response['e'], *private_key_user1))
    n_user2 = int(rsa_decrypt(response['n'], *private_key_user1))
    public_key_user2 = (e_user2, n_user2)

    # DES key (64-bit hex). Must be 16 hex characters.
    des_key = "AABB09182736CCDD"

    # Encrypt DES key with user2's public key using RSA
    encrypted_key = rsa_encrypt(des_key, *public_key_user2)

    # Send key to user2
    client_socket = socket.socket()
    client_socket.connect(('localhost', 6000))
    client_socket.send(json.dumps({"key": encrypted_key}).encode())

    # Encrypt and send a message
    plaintext = "Hello from user1!"
    encrypted_message = des_encrypt(plaintext, des_key)
    client_socket.send(json.dumps({"message": encrypted_message}).encode())
    client_socket.close()

if __name__ == '__main__':
    user1()
