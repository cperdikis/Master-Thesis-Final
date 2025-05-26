import time
from datetime import datetime

from helper_functions import *


def handle_client(conn, addr, context, connection_id):
    # thread_id = threading.get_ident()

    start_tls_handshake = time.perf_counter()
    # Step 4: Accept the client and wrap the connection with TLS
    tls_conn = context.wrap_socket(conn, server_side=True)

    tls_handshake_time = time.perf_counter() - start_tls_handshake
    logging.info(f"TLS 1.3 Handshake with {addr} completed in {tls_handshake_time:.6f} seconds")
    print(f"Secure connection established with {addr} using {tls_conn.version()}")

    try:
        start_keyexchange = time.perf_counter()
        # Step 5: Send Kyber768 public key securely over TLS connection
        tls_conn.sendall(server_mlkem_publickey)
        print("Sent Kyber768 public key to the client.", addr)
        tls_conn.sendall(server_ecdh_publickey_bytes)
        print("Sent ECDH public key to the client.", addr)
        tls_conn.sendall(server_pqc_signing_publickey)
        print("Sent Dilithium2 public key to the client.", addr)

        # Step 6: Receive ciphertext, ecdh public key and pqc public key from client securely over TLS
        ciphertext = tls_conn.recv(CIPHERTEXT_SIZE)
        client_ecdh_publickey_bytes = tls_conn.recv(ecdh_publickey_bytes_length)
        client_pqc_signing_publickey = tls_conn.recv(PUBLIC_KEY_SIZE_SIGNING)

        # Deserialize client's public key
        client_ecdh_publickey = serialization.load_pem_public_key(client_ecdh_publickey_bytes)

        # Log Key Exchange Phase time
        key_exchange_time = time.perf_counter() - start_keyexchange
        logging.info(f"Key Exchange Phase for {addr} completed in {key_exchange_time:.6f} seconds")

        # Step 7: Derive the ECDH and ML-KEM shared secrets and Hybrid Shared Key
        start_hybrid_key_generation = time.perf_counter()
        shared_ecdhsecret_server = server_ecdh_privatekey.exchange(ec.ECDH(), client_ecdh_publickey)
        shared_mlkemsecret_server = decrypt(server_mlkem_privatekey, ciphertext)

        aes_key = key_derivation_function(shared_ecdhsecret_server, shared_mlkemsecret_server)
        hybrid_key_generation_time = time.perf_counter() - start_hybrid_key_generation
        logging.info(
            f"Hybrid Key Generation Phase for {addr} completed in {hybrid_key_generation_time:.6f} seconds")

        print("Client-derived Kyber768 shared secret: ", shared_mlkemsecret_server)
        print("Client-derived ECDH shared secret: ", shared_ecdhsecret_server)

        while True:
            # Step 8: Sign Message
            message = b"Send File Header"
            start_signing = time.perf_counter()
            ecdsa_signature, pqc_signature = hybrid_sign(server_ecdh_privatekey,
                                                         server_pqc_signing_privatekey, message)
            signed_message = SignedMessage(message, ecdsa_signature, pqc_signature)
            signing_time = time.perf_counter() - start_signing
            logging.info(f"Hybrid signing for {addr} completed in {signing_time:.6f} seconds")
            print("Message Signed")

            # Step 9: Encrypt the message
            start_encryption = time.perf_counter()
            encrypted_message = encrypt_message(aes_key, signed_message.to_bytes())
            encryption_time = time.perf_counter() - start_encryption
            logging.info(
                f"Message Encryption for {addr} completed in {encryption_time:.6f} seconds")
            print("Message Encrypted")

            # Step 10: Send message asking file header
            tls_conn.sendall(encrypted_message.to_bytes())
            print("Sent encrypted message of length ", len(encrypted_message.to_bytes()), " to", addr)

            # Step 11: Receive file header
            encrypted_file_header = tls_conn.recv(5096)

            decrypted_file_header = decrypt_message(aes_key, EncryptedMessage.from_bytes(
                encrypted_file_header))
            received_signed_file_header = SignedMessage.from_bytes(decrypted_file_header)

            received_file_header = hybrid_verify(client_ecdh_publickey,
                                               client_pqc_signing_publickey,
                                               received_signed_file_header)
            file_header = FileHeader.from_bytes(received_file_header)
            file_name = file_header.file_name
            file_size = file_header.file_size

            print(f"Here is the file name: {file_name} and size: {file_size}")

            # Step 12: Receive image data streams
            total_time_to_verify = 0
            total_time_to_decrypt = 0
            total_time_to_receive = 0

            receive_dir = "client-side/uploads/"
            os.makedirs(receive_dir, exist_ok=True)  # Ensure the directory exists before monitoring

            with open("server-side/" + file_name, "wb") as f:
                print(f"Waiting to receive file from {addr} ...")
                logging.info(f"Waiting to receive file from {addr}")
                received_bytes = 0
                while received_bytes < file_size:
                    # Receiving 1 KB = 5754, 2KB = 7574, 3 KB = 9390, 4 KB = 11214
                    temp_time_to_receive = time.perf_counter()
                    encrypted_data_stream = tls_conn.recv(11214)
                    total_time_to_receive = total_time_to_receive + (time.perf_counter() - temp_time_to_receive)
                    if not encrypted_data_stream:
                        break
                    else:
                        # print(len(encrypted_data_stream))
                        # Decrypt the data chunk
                        temp_time_to_decrypt = time.perf_counter()
                        decrypted_data_stream = decrypt_message(aes_key, EncryptedMessage.from_bytes(
                            encrypted_data_stream))
                        received_signed_data_stream = SignedMessage.from_bytes(decrypted_data_stream)
                        total_time_to_decrypt = total_time_to_decrypt + (
                                time.perf_counter() - temp_time_to_decrypt)

                        # Verify signature of the data chunk
                        temp_time_to_verify = time.perf_counter()
                        try:
                            data_stream = hybrid_verify(client_ecdh_publickey,
                                                        client_pqc_signing_publickey,
                                                        received_signed_data_stream)
                        except Exception:
                            logging.error(f"fReceived Message from {addr} Compromised!!!")
                            print(f"Received Message from {addr} Compromised!!!")
                            break

                        total_time_to_verify = total_time_to_verify + (
                                time.perf_counter() - temp_time_to_verify)

                    f.write(data_stream)
                    received_bytes = received_bytes + len(data_stream)

            logging.info(
                f"Total Decryption Time for Message from {addr}: {total_time_to_decrypt:.6f} seconds")
            logging.info(
                f"Total Verification Time for Message from {addr}: {total_time_to_verify:.6f} seconds")
            logging.info(
                f"Total Receive Time for Message from {addr}: {total_time_to_receive:.6f} seconds")
            timestamp = datetime.now()
            log_time_metrics_to_csv(
                times_csv_filepath, timestamp, addr, connection_id, tls_handshake_time,
                key_exchange_time,
                hybrid_key_generation_time, encryption_time, -1, signing_time, -1,
                -1, -1, total_time_to_verify, total_time_to_decrypt, total_time_to_receive)

            # log and print conformation message that the file with name, has been received successfully
            logging.info(f"The file {file_name} was received successfully !")


    except Exception as e:
        print(f"Error with {addr}: {e}")
        logging.error(f"Error with {addr}: {e}")

    finally:
        tls_conn.close()

        # server_stop_rtt_event.set()
        # print("Waiting on rtt thread")
        # server_rtt_thread.join()
        print(f"Connection closed: {addr}\n")
        logging.info(f"Connection closed: {addr}")


if __name__ == "__main__":

    # Setup logging
    setup_logging("logs/server/server.log")
    times_csv_filepath = "logs/server/server_time_metrics.csv"
    setup_csv_time_logging(times_csv_filepath)
    server_ip = "localhost"
    server_id = 1
    connection_id = 1
    server_port = 12345
    server_rtt_thread_port = 5005

    # Step 1: Generate Server's key pair using Kyber768, ECDH (Curve: SECP256R1) and Dilithium
    server_ecdh_publickey, server_ecdh_privatekey, server_ecdh_publickey_bytes, ecdh_publickey_bytes_length = generate_ecdh_keys()
    server_mlkem_publickey, server_mlkem_privatekey = generate_mlkem_keys()
    server_pqc_signing_publickey, server_pqc_signing_privatekey = pqc_signing_generate_keypair()

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
    server.bind((server_ip, server_port))
    server.listen()

    print("Server is listening for secure TLS 1.3 connections...")

    while True:
        conn, addr = server.accept()



        # Note: A daemon thread runs in the background and automatically exits when the main program
        # ends, even if it's still running


        client_thread = threading.Thread(target=handle_client,
                                         args=(
                                             conn, addr, context, connection_id))
        client_thread.start()

        connection_id = connection_id + 1
