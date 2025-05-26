import socket
import ssl
import base64
import json
import time
import logging
import os
import threading
import csv

from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, \
    EllipticCurvePublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pqcrypto.sign.dilithium2 import generate_keypair as generate_dilithium2_keypair, sign, verify, \
    SIGNATURE_SIZE, PUBLIC_KEY_SIZE as PUBLIC_KEY_SIZE_SIGNING
from pqcrypto.kem.kyber1024 import generate_keypair as generate_kyber_keypair, decrypt, encrypt, \
    CIPHERTEXT_SIZE, PUBLIC_KEY_SIZE as PUBLIC_KEY_SIZE_KYBER

classic_encryption_name = "ECDH_SECP256R1"
pqc_encryption_name = "KYBER1024"
pqc_signing_name = "Dilithium2"


# Kyber Key Sizes and Shared Secret Lengths
# -----------------------------------------
# | Kyber Variant | Public Key Size | Secret Key Size | Ciphertext Size | Shared Secret Size |
# |--------------|----------------|-----------------|-----------------|-------------------|
# | Kyber-512    | 800 bytes       | 1632 bytes      | 768 bytes       | 32 bytes          |
# | Kyber-768    | 1184 bytes      | 2400 bytes      | 1088 bytes      | 32 bytes          |
# | Kyber-1024   | 1568 bytes      | 3168 bytes      | 1568 bytes      | 32 bytes          |
#
# - Public Key Size: The size of the public key used in key exchange.
# - Secret Key Size: The size of the private key.
# - Ciphertext Size: The size of the encrypted key material.
# - Shared Secret Size: The length of the derived shared secret (always 32 bytes).


# Key Generation Functions
def generate_ecdh_keys():
    privatekey = ec.generate_private_key(ec.SECP256R1())
    publickey = privatekey.public_key()
    # Serialize client's public key
    publickey_bytes = publickey.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return publickey, privatekey, publickey_bytes, len(publickey_bytes)


def generate_mlkem_keys():
    return generate_kyber_keypair()


# Key Derivation Functions
def key_derivation_function(classic_shared_secret, pq_shared_secret):
    # Concatenate the 2 secrets
    hybrid_secret = classic_shared_secret + pq_shared_secret
    hkdf = HKDF(
        algorithm=hashes.SHA3_512(),
        length=32,
        salt=None,
        info=b"Hybrid key",
    )
    hybrid_key = hkdf.derive(hybrid_secret)

    return hybrid_key


# Logging Functions

# Setting up general logging
def setup_logging(log_filename):
    # Sets up logging for the application, ensuring consistency across modules

    # Ensure the logs directory exists

    os.makedirs(os.path.dirname(log_filename), exist_ok=True)

    # Configure logging settings
    logging.basicConfig(
        filename=log_filename,
        level=logging.INFO,
        format="%(asctime)s - Thread %(thread)d - %(levelname)s - %(message)s",
    )

    logging.info("Logging initialized")


# Setting up logging timing results of a Session in csv
def setup_csv_time_logging(csv_filename):
    csv_headers = ["Timestamp",
                   "Client_IP", "Connection_ID", "TLS_Handshake_Time", "Key_Exchange_Time",
                   "Hybrid_Key_Generation_Time", "Encryption_Time", "Decryption_Time",
                   "Signing_Time",
                   "Signature_Verification_Time",
                   "Total_Signing_Time", "Total_Encryption_Time", "Total_Verifying_Time",
                   "Total_Decryption_Time", "Total_Time_To_Sent_Or_Receive"
                   ]
    os.makedirs(os.path.dirname(csv_filename), exist_ok=True)

    with open(csv_filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)  # Write header row


# Setting up logging for size factors of a Session in csv
def setup_csv_size_logging(csv_filename):
    csv_headers = ["Timestamp",
                   "Client_IP", "Connection_ID", "Encryption_Used", "Signing_Used",
                   "Classic_Encryption_SharedSecret_Length", "PQC_Encryption_SharedSecret_Length",
                   "Hybrid_AES_Key_Length", "Classical_Signature_Length",
                   "PQC_Signature_Length", "Signed_Msg_Length", "Encrypted_Msg_Length",
                   "Chunk_Size", "Original_Msg_Size"

                   ]
    os.makedirs(os.path.dirname(csv_filename), exist_ok=True)

    with open(csv_filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)  # Write header row


# Logging function for time metrics
def log_time_metrics_to_csv(csv_filename, timestamp, client_ip, connection_id, tls_handshake_time,
                            key_exchange_time,
                            hybrid_key_generation_time, encryption_time, decryption_time,
                            signing_time,
                            signature_verification_time,
                            total_time_to_sign, total_time_to_encrypt, total_time_to_verify,
                            total_time_to_decrypt, total_time_to_sent_or_receive):
    with open(csv_filename, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp,
                         client_ip, connection_id, tls_handshake_time, key_exchange_time,
                         hybrid_key_generation_time, encryption_time, decryption_time, signing_time,
                         signature_verification_time,
                         total_time_to_sign, total_time_to_encrypt, total_time_to_verify,
                         total_time_to_decrypt, total_time_to_sent_or_receive
                         ])


# Logging function for size metrics
def log_size_metrics_to_csv(csv_filename, timestamp, client_ip, connection_id, encryption_used,
                            signing_used,
                            classic_encryption_key_length, pqc_encryption_key_length,
                            hybrid_aes_key_length, classical_signature_length,
                            pqc_signature_length, signed_msg_length, encrypted_msg_length,
                            chunk_size, original_msg_size):
    with open(csv_filename, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp,
                         client_ip, connection_id, encryption_used, signing_used,
                         classic_encryption_key_length, pqc_encryption_key_length,
                         hybrid_aes_key_length, classical_signature_length,
                         pqc_signature_length, signed_msg_length, encrypted_msg_length, chunk_size,
                         original_msg_size
                         ])


# Setting up logging of the RTT in csv
def setup_client_rtt_logging(filepath, server_addr):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(server_addr)
        writer.writerow(["Timestamp", "RTT (ms)"])


def setup_server_rtt_logging(filepath, client_addr):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(client_addr)
        writer.writerow(["Timestamp", "RTT (ms)"])


# Logging function for the RTT csv
def log_client_rtt_to_csv(filepath, rtt):
    with open(filepath, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([time.perf_counter(), rtt])


def log_server_rtt_to_csv(filepath, rtt):
    with open(filepath, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([time.perf_counter(), rtt])


# File Header
class FileHeader:
    def __init__(self, file_name: str, file_size: int):
        self.file_name = file_name
        self.file_size = file_size

    def to_bytes(self) -> bytes:
        """Convert the file header to a bytes object for transmission."""
        message_dict = {
            "file_name": self.file_name,
            "file_size": self.file_size,

        }
        return json.dumps(message_dict).encode()

    @staticmethod
    def from_bytes(data: bytes):
        """Reconstruct the file header object from bytes."""
        message_dict = json.loads(data.decode())
        return FileHeader(
            message_dict["file_name"],
            message_dict["file_size"])



# Hybrid Signing

class SignedMessage:
    def __init__(self, message: bytes, classic_signature: bytes, pqc_signature: bytes):
        self.message = message
        self.classic_signature = classic_signature
        self.pqc_signature = pqc_signature

    def to_bytes(self) -> bytes:
        """Convert the signed message to a bytes object for transmission."""
        message_dict = {
            "message": base64.b64encode(self.message).decode(),
            "classic_signature": base64.b64encode(self.classic_signature).decode(),
            "pqc_signature": base64.b64encode(self.pqc_signature).decode()
        }
        return json.dumps(message_dict).encode()

    @staticmethod
    def from_bytes(data: bytes):
        """Reconstruct the SignedMessage object from bytes."""
        message_dict = json.loads(data.decode())
        return SignedMessage(
            base64.b64decode(message_dict["message"]),
            base64.b64decode(message_dict["classic_signature"]),
            base64.b64decode(message_dict["pqc_signature"]),
        )


def hybrid_sign(ecdsa_private: EllipticCurvePrivateKey, pqc_privatekey, message):
    # Create ECDSA signature
    ecdsa_signature = ecdsa_sign(ecdsa_private, message)
    # Create post-quantum signature
    pqc_signature = pqc_sign(pqc_privatekey, message)

    return ecdsa_signature, pqc_signature


def hybrid_verify(ecdsa_publickey: EllipticCurvePublicKey, pqc_publickey,
                  received_signed_message: SignedMessage):
    ecdsa_signature = received_signed_message.classic_signature
    pqc_signature = received_signed_message.pqc_signature
    message = received_signed_message.message
    if ecdsa_verify(ecdsa_publickey, message, ecdsa_signature) and pqc_verify(pqc_publickey,
                                                                              message,
                                                                              pqc_signature):
        return message
    else:
        raise Exception("Hybrid Signature Verification Failed!!!")


# PQC Signing
def pqc_signing_generate_keypair():
    public, private = generate_dilithium2_keypair()
    return public, private


def pqc_sign(privatekey, message):
    return sign(privatekey, message)


def pqc_verify(publickey, message, signature):
    return verify(publickey, message, signature)


# ECDSA Signing

def get_ecdsa_signature_length():
    privatekey = ec.generate_private_key(ec.SECP256R1())
    test_signature = privatekey.sign(b'test', ec.ECDSA(hashes.SHA256()))
    return len(test_signature)


def ecdsa_sign(privatekey: EllipticCurvePrivateKey, message):
    signature = privatekey.sign(
        message,
        ec.ECDSA(hashes.SHA256())
    )
    return signature


def ecdsa_verify(publickey: EllipticCurvePublicKey, message, signature):
    try:
        publickey.verify(
            signature,  # Extract ECDSA part
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return True
    except:
        return False


# AES Message Encryption/Decryption
class EncryptedMessage:
    def __init__(self, ciphertext: bytes, nonce: bytes, tag: bytes):
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.tag = tag

    def to_bytes(self) -> bytes:
        """Convert the encrypted message to a bytes object for transmission."""
        message_dict = {
            "ciphertext": base64.b64encode(self.ciphertext).decode(),
            "nonce": base64.b64encode(self.nonce).decode(),
            "tag": base64.b64encode(self.tag).decode()
        }
        return json.dumps(message_dict).encode()

    @staticmethod
    def from_bytes(data: bytes):
        """Reconstruct the EncryptedMessage object from bytes."""
        message_dict = json.loads(data.decode())
        return EncryptedMessage(
            base64.b64decode(message_dict["ciphertext"]),
            base64.b64decode(message_dict["nonce"]),
            base64.b64decode(message_dict["tag"])
        )


# AES-GCM Encryption Function

# Encrypt a byte stream using AES with GCM (Galois/Counter Mode) mode of cipher operation
def encrypt_message(aes_key: bytes, message: bytes) -> EncryptedMessage:
    nonce = os.urandom(12)  # Secure nonce (IV) for AES-GCM (12 bytes)

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce))
    encryptor = cipher.encryptor()

    ciphertext = encryptor.update(message) + encryptor.finalize()
    return EncryptedMessage(ciphertext, nonce, encryptor.tag)


# AES-GCM Decryption Function

# Decrypt an EncryptedMessage object using AES with GCM (Galois/Counter Mode) mode of cipher operation
def decrypt_message(aes_key: bytes, encrypted_msg: EncryptedMessage) -> bytes:
    # Using AES with GCM (Galois/Counter Mode) mode of cipher operation
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(encrypted_msg.nonce, encrypted_msg.tag))
    decryptor = cipher.decryptor()

    return decryptor.update(encrypted_msg.ciphertext) + decryptor.finalize()


# RTT measuring functions
def server_rtt_function(server_ip, server_port, server_csv_filepath, client_addr, connection_id,
                        server_stop_rtt_event):
    setup_server_rtt_logging(server_csv_filepath, client_addr)

    server_rtt_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_rtt_socket.bind((server_ip, server_port))

    print("This is what i received: ", server_rtt_socket.recvfrom(1024))
    start_time = None
    while not server_stop_rtt_event.is_set():
        try:

            data, addr = server_rtt_socket.recvfrom(4)

            if addr != client_addr:
                logging.error(f"RTT Server Error, wrong client ip address detected: {e}")
            elif data == b'ping':
                server_rtt_socket.sendto(b'pong', addr)
                start_time = time.perf_counter()
            elif data == b'peng' and start_time is not None:
                rtt = (time.perf_counter() - start_time) * 1000  # Convert to ms
                log_server_rtt_to_csv(server_csv_filepath, rtt)
                start_time = None

        except Exception as e:
            print(f"RTT Server Error: {e}")
            logging.error(f"RTT Server Error: {e}")
    print("RTT Server Shutdown Successfully")
    logging.info("RTT Server Shutdown Successfully")


def client_rtt_function(server_ip, server_port, client_csv_filepath, frequency,
                        client_stop_rtt_event):
    setup_client_rtt_logging(client_csv_filepath, server_ip)
    time.sleep(1)
    while not client_stop_rtt_event.is_set():
        try:

            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:

                ping_message = b"ping"
                start_time = time.perf_counter()

                sock.sendto(ping_message, (server_ip, server_port))

                try:
                    pong, addr = sock.recvfrom(4)

                    if addr != server_ip:
                        logging.error(f"RTT Client Error, wrong server ip address detected: {e}")
                    elif pong == b"pong":

                        rtt = (time.perf_counter() - start_time) * 1000  # Convert to milliseconds

                        log_client_rtt_to_csv(client_csv_filepath, rtt)
                        # Send pong_ack to server
                        sock.sendto(b"peng", (server_ip, server_port))

                except socket.timeout:
                    print("RTT request timed out")
                    logging.info("RTT request timed out")
        except Exception as e:
            print(f"CLIENT RTT thread error: {e}")
            logging.error(f"RTT thread error: {e}")

        time.sleep(frequency)
    print("RTT Client Shutdown Successfully")
    logging.info("RTT Client Shutdown Successfully")
