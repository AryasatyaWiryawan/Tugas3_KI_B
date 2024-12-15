import socket
import json
from rsa_util import rsa_encrypt, rsa_decrypt
from des_util import des_encrypt

# Private key of User1
private_key_user1 = (7, 143)

def user1():
    # Step 1: Get User2's public key from PKA
    pka_socket = socket.socket()
    pka_socket.connect(('localhost', 5000))
    pka_socket.send(b'user1')  # Request User2's public key
    response = json.loads(pka_socket.recv(1024).decode())
    pka_socket.close()

    # Step 2: Decrypt User2's public key using User1's private key
    e_user2 = rsa_decrypt(response['e'], *private_key_user1)
    n_user2 = rsa_decrypt(response['n'], *private_key_user1)
    public_key_user2 = (e_user2, n_user2)
    print("Public key (e, n) for User2:", public_key_user2)

    # Step 3: Generate and encrypt DES key
    des_key = "AABB09182736CCDD"  # 64-bit DES key (16 hex characters)
    encrypted_key = rsa_encrypt(int(des_key, 16), *public_key_user2)

    # Step 4: Send encrypted DES key and encrypted message to User2
    client_socket = socket.socket()
    client_socket.connect(('localhost', 6000))
    client_socket.send(json.dumps({"key": encrypted_key}).encode())

    plaintext = "Hello from User1!"  # Message to encrypt
    encrypted_message = des_encrypt(plaintext, des_key)  # Encrypt message using DES key
    print("Encrypted message:", encrypted_message)

    client_socket.send(json.dumps({"message": encrypted_message}).encode())
    client_socket.close()

if __name__ == '__main__':
    user1()
