import socket
import json
from rsa_util import rsa_decrypt
from des_util import des_decrypt

# Private key of User2
private_key_user2 = (11, 187)

def user2():
    server = socket.socket()
    server.bind(('localhost', 6000))
    server.listen(1)
    print("User2 is waiting for messages on localhost:6000...")
    conn, _ = server.accept()

    # Step 1: Receive encrypted DES key
    data = json.loads(conn.recv(1024).decode())
    encrypted_key = data['key']
    des_key = hex(rsa_decrypt(encrypted_key, *private_key_user2))[2:].upper().zfill(16)
    print("Decrypted DES key (User2):", des_key)

    # Step 2: Receive encrypted message
    data = json.loads(conn.recv(1024).decode())
    encrypted_message = data['message']
    print("Encrypted message (User2):", encrypted_message)

    # Step 3: Decrypt the message using the DES key
    decrypted_message = des_decrypt(encrypted_message, des_key)
    print("Decrypted message (User2):", decrypted_message)

    conn.close()

if __name__ == '__main__':
    user2()