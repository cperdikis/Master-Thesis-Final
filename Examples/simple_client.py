import socket
import ssl
import os
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
    csv_headers = ["Timestamp", "Filename_Send_Time", "File_Send_Time"]
    os.makedirs(os.path.dirname(csv_filename), exist_ok=True)
    with open(csv_filename, mode="w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(csv_headers)


def log_time_metrics_to_csv(csv_filename, filename_send_time, file_send_time):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(csv_filename, mode="a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([timestamp, filename_send_time, file_send_time])

def wait_for_server_header_request(tls_conn):
    msg = tls_conn.recv(1024)
    while msg != b"Send File Header":
        msg = tls_conn.recv(1024)
    print("File Header Requested form Server")
def wait_for_file(directory):
    print(f"Waiting for files in {directory}...")
    while True:
        files = os.listdir(directory)
        if files:
            return os.path.join(directory, files[0])
        time.sleep(5)


def send_file(tls_conn, file_path, csv_filename):
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    file_header = FileHeader(file_name, file_size)
    # Measure time taken to send the filename
    start_time = time.time()
    tls_conn.sendall(file_header.to_bytes())  # Send filename
    filename_send_time = time.time() - start_time
    print(f"Sent file_header: {file_header} (Time: {filename_send_time:.6f} sec)")

    # Measure time taken to send the whole file
    start_time = time.time()
    with open(file_path, "rb") as f:
        while (chunk := f.read(4096)):
            tls_conn.sendall(chunk)
    file_send_time = time.time() - start_time
    print(f"File {file_name} sent successfully! (Time: {file_send_time:.6f} sec)")

    # Log time metrics
    log_time_metrics_to_csv(csv_filename, filename_send_time, file_send_time)
    os.remove(file_path)  # Remove the file after sending


def run_client(server_ip, server_port, csv_filename):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1  # Disable older versions
    context.load_verify_locations("certificates/server.crt")

    with socket.create_connection((server_ip, server_port)) as sock:
        with context.wrap_socket(sock, server_hostname=server_ip) as tls_conn:
            print(f"Connected to server using {tls_conn.version()}")

            upload_dir = "client-side/uploads/"
            os.makedirs(upload_dir, exist_ok=True)

            while True:
                wait_for_server_header_request(tls_conn)
                file_path = wait_for_file(upload_dir)
                send_file(tls_conn, file_path, csv_filename)


if __name__ == "__main__":
    server_ip = "localhost"
    server_port = 12345
    csv_filename = "logs/simple_client_time_metrics.csv"
    setup_csv_logging(csv_filename)

    run_client(server_ip, server_port, csv_filename)

