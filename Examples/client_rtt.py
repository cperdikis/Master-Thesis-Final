from datetime import datetime
import socket
import threading
import time
import csv
import os

def start_client(server_ip, server_port):
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect((server_ip, server_port))
    print(f"RTT Connected to server {server_ip}:{server_port}")

    filepath = f"./logs/client/client_rtt/rtt_client_log.csv"
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "RTT (ms)"])

    while True:
        try:
            start_time = time.time()
            client.sendall(b"ping")
            data = client.recv(4)
            if not data or data.decode() != "pong":
                break
            rtt = (time.time() - start_time) * 1000  # Convert to milliseconds

            client.sendall(b"peng")

            with open(filepath, mode='a', newline='') as file:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                writer = csv.writer(file)
                writer.writerow([timestamp, rtt])

            time.sleep(1)
        except KeyboardInterrupt:
            print("Client shutting down...")
            break
        except Exception as e:
            print(f"Error: {e}")
            break

    client.close()

if __name__ == "__main__":
    print("Start RTT Client...")
    server_ip = "localhost"
    server_port = 5005

    start_client(server_ip, server_port)