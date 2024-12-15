import socket
import json
from rsa_util import rsa_encrypt, rsa_decrypt
from des_util import des_encrypt_block, generate_keys

private_key_user1 = (7, 143)

def user1():
    # Mengambil public key user2 dari PKA
    pka_socket = socket.socket()
    pka_socket.connect(('localhost', 5000))
    pka_socket.send(b'user1')
    response = json.loads(pka_socket.recv(1024).decode())
    e_user2 = int(rsa_decrypt(response['e'], *private_key_user1))
    n_user2 = int(rsa_decrypt(response['n'], *private_key_user1))
    public_key_user2 = (e_user2, n_user2)
    pka_socket.close()

    # Enkripsi kunci DES
    des_key = "AABBCCDDEEFF1122"
    encrypted_key = rsa_encrypt(des_key, *public_key_user2)

    # Mengirim kunci ke user2
    client_socket = socket.socket()
    client_socket.connect(('localhost', 6000))
    client_socket.send(json.dumps({"key": encrypted_key}).encode())

    # Mengirim pesan terenkripsi
    plaintext = "Hello from user1!"
    keys = generate_keys(des_key)
    encrypted_message = des_encrypt_block(plaintext, keys)
    client_socket.send(json.dumps({"message": encrypted_message}).encode())
    client_socket.close()
