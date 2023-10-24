import socket
import json
import hashlib
import base64
from Crypto.Cipher import AES

AUTH_APP_SHARED_KEY = b'\xf3\xb9N\xc8\xa80\xe8\xf8\xc48\x85r\xe3=z\xa7'
AUTH_APP_SHARED_NONCE = b'\xcc\xa5t\t4\x02\xd9\xe9\x0b\x1b\x82\x8c$\x083\xed'
CLIENT_AUTH_SHARED_NONCE = b'L\x91\x848\xca\\s\xc8\xc5l\xa7\xbb\xb1\xfa\xd6\x0f'

LISTEN_IP = '0.0.0.0'  # Listen on all available network interfaces
LISTEN_PORT = 9000  # Choose a port for the server

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
sock.listen(5)
print(f"Auth Server is listening on {LISTEN_IP}:{LISTEN_PORT}")

while True:
    client_socket, client_address = sock.accept()
    print(f"Accepted connection from {client_address}")

    data = client_socket.recv(1024)
    if data is None:
        break

    print(f"Received credentials from client")
    creds = json.loads(data)
    username = creds["username"]
    password = creds["password"]

    # STEP 3: Auth server uses creds to send an http request to the oauth provider
    # TODO: this is a command line command, change to code
    # curl -u testclient:testpass http://localhost/token.php -d 'grant_type=client_credentials'

    # TODO: see what a response from the server looks like with bad creds and change the condition
    if False:
        # STEP 4: If creds are wrong, return the following json to the client
        client_response = '{“auth”:”fail”, “token”:””}'
        client_response = client_response.encode()
    else:
        # STEP 5: If the creds are right, the ouath server returns a json response
        # To get things working, a fake response will be used for now
        oauth_response = '{"access_token":"03807cb390319329bdf6c777d4dfae9c0d3b3c35","expires_in":3600,"token_type":"bearer","scope":null}'

        # STEP 6: Encrypt the json response that contains the token with a key known only to the auth and app servers
        aes = AES.new(AUTH_APP_SHARED_KEY, AES.MODE_EAX, nonce=AUTH_APP_SHARED_NONCE)
        encrypted_oauth_reponse = aes.encrypt(oauth_response.encode())

        # json doenst like raw bytes in one of its fields. base64 encode it
        enc_base64_oauth = base64.b64encode(encrypted_oauth_reponse)
        enc_base64_oauth_ascii = enc_base64_oauth.decode() 

        # STEP 7: Construct a json response with the encrypted json reply from the oauth server
        plaintext_response = f'{{"auth":"success", "token":"{enc_base64_oauth_ascii}"}}'

        # STEP 8: Encrypt the response in step 7 with the SHA256 hash of the user's password as the key
        sha256_obj = hashlib.sha256()
        sha256_obj.update(password.encode())
        pass_sha256 = sha256_obj.digest()
        aes = AES.new(pass_sha256, AES.MODE_EAX, nonce=CLIENT_AUTH_SHARED_NONCE)
        client_response = aes.encrypt(plaintext_response.encode())

    client_socket.send(client_response)
    client_socket.close()

# Close the server socket
sock.close()
