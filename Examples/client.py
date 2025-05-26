import logging
import time
from datetime import datetime

from helper_functions import *

def wait_for_server_header_request(tls_conn, aes_key, server_ecdh_publickey,server_pqc_signing_publickey):
    message = b""
    # Step 7: Receive message
    while (message != b"Send File Header"):
        encrypted_message = tls_conn.recv(4096)

        start_decryption = time.perf_counter()
        # Step 8: Decrypt message
        decrypted_message = decrypt_message(aes_key,
                                            EncryptedMessage.from_bytes(
                                                encrypted_message))
        decryption_time = time.perf_counter() - start_decryption
        logging.info(
            f"Message Decryption for Client {client_id} completed in {decryption_time:.6f} seconds")

        start_signing_verification_time = time.perf_counter()
        # Step 9: Verify signature
        received_signed_message = SignedMessage.from_bytes(decrypted_message)
        try:
            message = hybrid_verify(server_ecdh_publickey, server_pqc_signing_publickey,
                                    received_signed_message)
        except Exception:
            logging.error("fReceived Message Compromised!!!")
            print("Received Message Compromised!!!")

        signing_verification_time = time.perf_counter() - start_signing_verification_time
        logging.info(
            f"Hybrid Signing Verification for Client {client_id} completed in {signing_verification_time:.6f} seconds")

        logging.info(f"Message received from Server is {message}")
        print(f"Message received from Server is {message}")

    logging.info("File Header Requested form Server")
    print("File Header Requested form Server")
    return decryption_time, signing_verification_time
def wait_for_file(directory):
    logging.info(f"Waiting for files in {directory}...")
    print(f"Waiting for files in {directory}...")
    while True:
        files = os.listdir(directory)
        if files:
            return os.path.join(directory, files[0])  # Select the first file found
        time.sleep(5)  # Avoid excessive CPU usage


def run_client(server_ip, server_port, client_id, connection_id):
    print("Client " + str(connection_id) + " is running...")

    # Setup logging
    setup_logging("logs/client/client.log")
    times_csv_filepath = "logs/client/client_time_metrics.csv"
    size_csv_filepath = "logs/client/client_size_metrics.csv"
    setup_csv_time_logging(times_csv_filepath)
    setup_csv_size_logging(size_csv_filepath)

    # Generate ECDH key pair (Curve: SECP256R1) and Dilithium
    client_ecdh_publickey, client_ecdh_privatekey, client_ecdh_publickey_bytes, ecdh_publickey_bytes_length = generate_ecdh_keys()
    client_pqc_signing_publickey, client_pqc_signing_privatekey = pqc_signing_generate_keypair()

    # Step 1: Create TLS 1.3 SSL context for client
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3  # Enforce TLS 1.3
    context.maximum_version = ssl.TLSVersion.TLSv1_3  # Ensure only TLS 1.3
    context.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1  # Disable older versions

    # Load CA certificate to verify the server
    context.load_verify_locations("certificates/server.crt")
    # Optional but recommended:
    context.check_hostname = False  # Skip CN/SAN matching, since it's self-signed
    context.verify_mode = ssl.CERT_REQUIRED


    # Step 2: Connect to server
    with socket.create_connection((server_ip, server_port)) as sock:
        start_tls = time.perf_counter()
        with context.wrap_socket(sock, server_hostname=server_ip) as tls_conn:

            tls_handshake_time = time.perf_counter() - start_tls

            logging.info(
                f"TLS 1.3 Handshake completed in {tls_handshake_time:.6f} seconds")
            print(f"Connected to server using {tls_conn.version()}")
            print("Server Certificate:", tls_conn.getpeercert())

            start_keyexchange = time.perf_counter()
            # Step 3: Receive Kyber768 public key from server securely over TLS
            server_mlkem_publickey = tls_conn.recv(PUBLIC_KEY_SIZE_KYBER)
            print("Received Kyber768 public key from server.")
            server_ecdh_publickey_bytes = tls_conn.recv(ecdh_publickey_bytes_length)
            print("Received ECDH public key from server.")
            server_pqc_signing_publickey = tls_conn.recv(PUBLIC_KEY_SIZE_SIGNING)
            print("Received Dilithium2 public key from server.")

            server_ecdh_publickey = serialization.load_pem_public_key(server_ecdh_publickey_bytes)

            # Step 4: Derive ML-KEM shared secret
            ciphertext, shared_mlkemsecret_client = encrypt(server_mlkem_publickey)

            # Step 5: Send ciphertext, client's ecdh public key and client's pqc public key
            tls_conn.sendall(ciphertext)
            tls_conn.sendall(client_ecdh_publickey_bytes)
            tls_conn.sendall(client_pqc_signing_publickey)

            # Log Key Exchange Phase time
            key_exchange_time = time.perf_counter() - start_keyexchange
            logging.info(
                f"Key Exchange Phase for Client {client_id} completed in {key_exchange_time:.6f} seconds")

            start_hybrid_key_generation = time.perf_counter()
            # Step 6: Derive ECDH and ML-KEM shared secret and Hybrid Shared Key
            shared_ecdhsecret_client = client_ecdh_privatekey.exchange(ec.ECDH(),
                                                                       server_ecdh_publickey)
            aes_key = key_derivation_function(shared_ecdhsecret_client, shared_mlkemsecret_client)

            hybrid_key_generation_time = time.perf_counter() - start_hybrid_key_generation
            logging.info(
                f"Hybrid Key Generation Phase for Client {client_id} completed in {hybrid_key_generation_time:.6f} seconds")

            print("Client-derived Kyber768 shared secret: ", shared_mlkemsecret_client)
            print("Client-derived ECDH shared secret: ", shared_ecdhsecret_client)



            # Step 10: Send data streams of an image

            upload_dir = "client-side/uploads/"
            os.makedirs(upload_dir, exist_ok=True)  # Ensure the directory exists before monitoring

            while True:
                # Waiting for server request of file header
                decryption_time, signing_verification_time = wait_for_server_header_request(tls_conn, aes_key, server_ecdh_publickey,
                                               server_pqc_signing_publickey)
                # Wait for a file to enter the directory
                file_path = wait_for_file(upload_dir)

                file_name = os.path.basename(file_path)
                file_size = os.path.getsize(file_path)
                file_header = FileHeader(file_name, file_size)
                logging.info(f"New file detected: {file_name} with size {file_size}")
                print(f"New file detected: {file_name} with size {file_size}")

                ecdsa_signature, pqc_signature = hybrid_sign(client_ecdh_privatekey,
                                                             client_pqc_signing_privatekey,
                                                             file_header.to_bytes())
                signed_data_stream = SignedMessage(file_header.to_bytes(), ecdsa_signature,
                                                   pqc_signature)

                encrypted_data_stream = encrypt_message(aes_key,
                                                        signed_data_stream.to_bytes())
                tls_conn.sendall(encrypted_data_stream.to_bytes())
                print(f"Length {len(encrypted_data_stream.to_bytes())}")

                total_time_to_sign = 0
                total_time_to_encrypt = 0
                total_time_to_sent = 0

                ecdsa_signature_len = 0
                pqc_signature_len = 0
                signed_data_stream_len = 0
                encrypted_data_stream_len = 0



                with open(file_path, "rb") as f:
                    chunk_size = 1024 * 4  # Each chunk is 4Kb
                    while (data_stream := f.read(chunk_size)):
                        # Sign the data chunk
                        temp_time_to_sign = time.perf_counter()
                        ecdsa_signature, pqc_signature = hybrid_sign(client_ecdh_privatekey,
                                                                     client_pqc_signing_privatekey,
                                                                     data_stream)
                        signed_data_stream = SignedMessage(data_stream, ecdsa_signature,
                                                           pqc_signature)
                        total_time_to_sign = total_time_to_sign + (time.perf_counter() - temp_time_to_sign)
                        # Encrypt the data chunk
                        temp_time_to_encrypt = time.perf_counter()
                        encrypted_data_stream = encrypt_message(aes_key,
                                                                signed_data_stream.to_bytes())
                        total_time_to_encrypt = total_time_to_encrypt + (
                                time.perf_counter() - temp_time_to_encrypt)

                        # Send the data chunk
                        temp_time_to_sent = time.perf_counter()
                        tls_conn.sendall(encrypted_data_stream.to_bytes())
                        total_time_to_sent = total_time_to_sent + (time.perf_counter() - temp_time_to_sent)

                        ecdsa_signature_len = max(ecdsa_signature_len, len(ecdsa_signature))
                        pqc_signature_len = max(pqc_signature_len, len(pqc_signature))
                        signed_data_stream_len = max(signed_data_stream_len,
                                                     len(signed_data_stream.to_bytes()))
                        encrypted_data_stream_len = max(encrypted_data_stream_len,
                                                        len(encrypted_data_stream.to_bytes()))

                        # print(len(encrypted_data_stream.to_bytes()))
                logging.info(f"Total Signing Time for Message: {total_time_to_sign:.6f} seconds")
                logging.info(
                    f"Total Encryption Time for Message: {total_time_to_encrypt:.6f} seconds")
                logging.info(
                    f"Total Sent Time for Message: {total_time_to_sent:.6f} seconds")
                timestamp = datetime.now()

                log_time_metrics_to_csv(
                    times_csv_filepath, timestamp, client_id, connection_id, tls_handshake_time,
                    key_exchange_time,
                    hybrid_key_generation_time, -1, decryption_time, -1, signing_verification_time,
                    total_time_to_sign, total_time_to_encrypt, -1, -1, total_time_to_sent)

                log_size_metrics_to_csv(size_csv_filepath, timestamp, client_id, connection_id,
                                        classic_encryption_name + "+" + pqc_encryption_name,
                                        pqc_signing_name,
                                        len(shared_ecdhsecret_client),
                                        len(shared_mlkemsecret_client),
                                        len(aes_key), ecdsa_signature_len, pqc_signature_len,
                                        signed_data_stream_len,
                                        encrypted_data_stream_len, chunk_size, file_size)

                os.remove(file_path)

                logging.info(f"File {file_path} sent and deleted.")
                print(f"File {file_path} sent and deleted.")

            # client_stop_rtt_event.set()
            # client_rtt_thread.join()


if __name__ == "__main__":
    client_id = 1
    connection_id = 1
    server_port = 12345
    server_ip = "localhost"


    # client_rtt_thread.start()
    run_client(server_ip, server_port, client_id, connection_id)
