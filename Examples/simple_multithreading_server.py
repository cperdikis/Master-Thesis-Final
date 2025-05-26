import socket
import ssl
import os
import threading
import time
import csv
import json
from datetime import datetime

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
def setup_csv_logging(csv_filename):
    csv_headers = ["Timestamp", "Client_IP", "Filename_Receive_Time", "File_Receive_Time"]
    os.makedirs(os.path.dirname(csv_filename), exist_ok=True)
    with open(csv_filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)


def log_time_metrics_to_csv(csv_filename, client_ip, filename_receive_time, file_receive_time):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(csv_filename, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, client_ip, filename_receive_time, file_receive_time])


def handle_client(conn, addr, csv_filename):
    print(f"Secure connection established with {addr} using {conn.version()}")
    try:
        while True:
            print("Requesting File Header")
            tls_conn.sendall(b"Send File Header")
            # Step 1: Receive the filename and log time
            start_time = time.perf_counter()
            file_header_bytes = conn.recv(1024)
            filename_receive_time = time.perf_counter() - start_time
            file_header = FileHeader.from_bytes(file_header_bytes)
            file_name = file_header.file_name
            file_size = file_header.file_size

            print(f"Receiving file: {file_name} (Time: {filename_receive_time:.6f} sec)")

            # Step 2: Receive and save the file in 4K chunks, log total time
            save_path = os.path.join("server-side/", file_name)
            os.makedirs(os.path.dirname(save_path), exist_ok=True)

            start_time = time.perf_counter()
            with open(save_path, "wb") as f:
                received_bytes = 0
                while received_bytes < file_size:
                    data = conn.recv(4096)

                    if not data:
                        print("No data !")
                        break
                    f.write(data)
                    received_bytes = received_bytes + len(data)

            file_receive_time = time.perf_counter() - start_time

            print(f"File {file_name} received successfully! (Time: {file_receive_time:.6f} sec)")
            log_time_metrics_to_csv(csv_filename, addr[0], filename_receive_time, file_receive_time)

    except Exception as e:
        print(f"Error with {addr}: {e}")
    finally:
        conn.close()
        print(f"Connection closed: {addr}\n")


if __name__ == "__main__":
    server_ip = "192.168.1.106"
    server_port = 12345
    csv_filename = "logs/simple_server_time_metrics.csv"
    setup_csv_logging(csv_filename)

    # Step 1: Create TLS 1.3 SSL context
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1  # Disable older versions
    # Load certificate and private key (must be pre-generated using OpenSSL)
    context.load_cert_chain(certfile="certificates/server.crt", keyfile="certificates/server.key")

    # Step 2: Start the server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, server_port))
    server.listen()
    print("Server is listening for secure TLS 1.3 connections...")

    while True:
        conn, addr = server.accept()
        tls_conn = context.wrap_socket(conn, server_side=True)

        client_thread = threading.Thread(target=handle_client, args=(tls_conn, addr, csv_filename))
        client_thread.start()