import socket
import json
import base64
from Crypto.Cipher import AES

AUTH_APP_SHARED_KEY = b'\xf3\xb9N\xc8\xa80\xe8\xf8\xc48\x85r\xe3=z\xa7'
AUTH_APP_SHARED_NONCE = b'\xcc\xa5t\t4\x02\xd9\xe9\x0b\x1b\x82\x8c$\x083\xed'

LISTEN_IP = '0.0.0.0'  # Listen on all available network interfaces
LISTEN_PORT = 9001  # Choose a port for the server

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
sock.listen(5)
print(f"App Server is listening on {LISTEN_IP}:{LISTEN_PORT}")

while True:
    client_socket, client_address = sock.accept()
    print(f"Accepted connection from {client_address}")

    data = client_socket.recv(1024)
    if data is None:
        break
    
    client_data = json.loads(data)
    auth = client_data["auth"]
    token = client_data["token"]
    decoded_token = base64.b64decode(token.encode())

    if auth == "success":
        aes = AES.new(AUTH_APP_SHARED_KEY, AES.MODE_EAX, nonce=AUTH_APP_SHARED_NONCE)
        dec_token = aes.decrypt(decoded_token)
        print("Decrypted oauth token: ", dec_token.decode())
        response = "Authenticated. Welcome to the application!"
    else:
        response = "Access to application is denied. Not authenticated"

    # STEP 10: Decrpyt the token sent by the client using AUTH_APP_SHARED_KEY, which will signify its validity

    # Send login status message
    client_socket.send(response.encode())
    client_socket.close()

# Close the server socket
sock.close()