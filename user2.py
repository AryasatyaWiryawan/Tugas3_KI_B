# user2.py
import socket
import json
from rsa_util import rsa_decrypt
from des_util import des_decrypt

private_key_user2 = (11, 187)

def user2():
    server = socket.socket()
    server.bind(('localhost', 6000))
    server.listen(1)
    conn, _ = server.accept()

    # Receive encrypted DES key
    data = json.loads(conn.recv(1024).decode())
    encrypted_key = data['key']
    des_key = rsa_decrypt(encrypted_key, *private_key_user2)

    # Receive encrypted message
    data = json.loads(conn.recv(1024).decode())
    encrypted_message = data['message']
    decrypted_message = des_decrypt(encrypted_message, des_key)

    print("Decrypted message:", decrypted_message)
    conn.close()

if __name__ == '__main__':
    user2()
