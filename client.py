# pycryptodome is required 
import socket
import json
import hashlib
from Crypto.Cipher import AES

CLIENT_AUTH_SHARED_NONCE = b'L\x91\x848\xca\\s\xc8\xc5l\xa7\xbb\xb1\xfa\xd6\x0f'

AUTH_SRV_IP = '127.0.0.1'
AUTH_SRV_PORT = 9000

APP_SRV_IP = '127.0.0.1'
APP_SRV_PORT = 9001

auth_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
app_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# STEP 1: User enters creds into the client application

user = input("Username: ")
password = input("Password: ")
creds = f'{{"username":"{user}", "password":"{password}"}}'

try:
    # Connect to the server
    auth_sock.connect((AUTH_SRV_IP, AUTH_SRV_PORT))
    print(f"Connected to {AUTH_SRV_IP}:{AUTH_SRV_PORT}")

    # STEP 2: Client sends creds to the authentication server
    print(f"Sending credentials to authentication server...")
    auth_sock.sendall(creds.encode())

    # STEP 9: Recieve encrypted json response with the token and decrypt it using SHA256 hash of the password and send
    response = auth_sock.recv(1024)
    sha256_obj = hashlib.sha256()
    sha256_obj.update(password.encode())
    pass_sha256 = sha256_obj.digest()
    aes = AES.new(pass_sha256, AES.MODE_EAX, nonce=CLIENT_AUTH_SHARED_NONCE)
    token = aes.decrypt(response)
    print("Auth server response:", token.decode())

    # Send decrypted response to the app server for validation
    app_sock.connect((APP_SRV_IP, APP_SRV_PORT))
    print(f"Connected to {APP_SRV_IP}:{APP_SRV_PORT}")
    app_sock.sendall(token)
    response = app_sock.recv(1024)
    print("App server response:", response.decode())

except Exception as e:
    print(f"ERROR: {e}")

finally:
    # Close the socket
    auth_sock.close()
    pass
