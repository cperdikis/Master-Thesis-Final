import socket
import ssl
import subprocess

from cryptography.hazmat.primitives import serialization
from pqcrypto.kem.kyber768 import generate_keypair, decrypt, CIPHERTEXT_SIZE
from cryptography.hazmat.primitives.asymmetric import ec
from helper_functions import *

# Step 1: Generate Server's key pair using Kyber768 and ECDH (Curve: SECP256R1)
server_mlkem_publickey, server_mlkem_privatekey = generate_keypair()
server_ecdh_publickey, server_ecdh_privatekey, server_ecdh_publickey_bytes, ecdh_publickey_bytes_length = generate_ecdh_key()

# Step 2: Create TLS 1.3 SSL context
context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
context.minimum_version = ssl.TLSVersion.TLSv1_3  # Enforce TLS 1.3
context.maximum_version = ssl.TLSVersion.TLSv1_3  # Ensure only TLS 1.3
context.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1  # Disable older versions

# Use strong TLS 1.3 cipher suites "TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256"

# Load server certificate and private key (generate with OpenSSL beforehand)
context.load_cert_chain(certfile="certificates/server.crt", keyfile="certificates/server.key")
print(context.get_ciphers())
# Step 3: Start server and wait for TLS connection
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(('localhost', 12345))
server.listen()

print("Server is listening for secure TLS 1.3 connections...")

# Step 4: Accept the client and wrap the connection with TLS
conn, addr = server.accept()
tls_conn = context.wrap_socket(conn, server_side=True)
print(f"Secure connection established with {addr} using {tls_conn.version()}")

# Step 5: Send Kyber512 public key securely over TLS connection
tls_conn.sendall(server_mlkem_publickey)
print("Sent Kyber512 public key to the client.", addr)
tls_conn.sendall(server_ecdh_publickey_bytes)
print("Sent ECDH public key to the client.", addr)

# Step 6: Receive ciphertext from client securely over TLS
ciphertext = tls_conn.recv(CIPHERTEXT_SIZE)
client_ecdh_publickey_bytes = tls_conn.recv(ecdh_publickey_bytes_length)
# Deserialize client's public key
client_ecdh_publickey = serialization.load_pem_public_key(client_ecdh_publickey_bytes)

# Step 7: Derive the ECDH and ML-KEM shared secrets
shared_ecdhsecret_server = server_ecdh_privatekey.exchange(ec.ECDH(), client_ecdh_publickey)
shared_mlkemsecret_server = decrypt(server_mlkem_privatekey, ciphertext)

print("Client-derived Kyber512 shared secret: ", shared_mlkemsecret_server)
print("Client-derived ECDH shared secret: ", shared_ecdhsecret_server)

message = b"Testing secure messaging"

aes_key = key_derivation_function(shared_ecdhsecret_server, shared_mlkemsecret_server)
encrypted_message = encrypt_message(aes_key, message)

tls_conn.sendall(encrypted_message.to_bytes())
print("Server sent data")

# Close connections
tls_conn.close()
server.close()

if __name__ == "__main__":
    print("Server is running...")
