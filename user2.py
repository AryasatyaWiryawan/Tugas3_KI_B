import socket
import json
from rsa_util import rsa_decrypt
from des_util import des_decrypt_block, generate_keys

private_key_user2 = (11, 187)

def user2():
    server = socket.socket()
    server.bind(('localhost', 6000))
    server.listen(1)
    conn, _ = server.accept()

    # Menerima kunci DES terenkripsi
    data = json.loads(conn.recv(1024).decode())
    encrypted_key = data['key']
    des_key = rsa_decrypt(encrypted_key, *private_key_user2)

    # Menerima pesan terenkripsi
    data = json.loads(conn.recv(1024).decode())
    encrypted_message = data['message']
    keys = generate_keys(des_key)
    decrypted_message = des_decrypt_block(encrypted_message, keys)

    print("Decrypted message:", decrypted_message)
    conn.close()
