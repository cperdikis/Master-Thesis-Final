import socket
import threading
import time
import csv
import os
from datetime import datetime


def handle_client(client_socket, client_address):
    ip, port = client_address
    filepath = f"./logs/server/server_rtt/{ip}.csv"
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Timestamp", "RTT (ms)"])

    while True:
        try:
            data = client_socket.recv(4)
            if not data or data.decode() != "ping":
                break

            start_time = time.perf_counter()
            client_socket.sendall(b"pong")
            data = client_socket.recv(4)
            if not data or data.decode() != "peng":
                break

            rtt = (time.perf_counter() - start_time) * 1000  # Convert to milliseconds

            with open(filepath, mode='a', newline='') as file:
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
                writer = csv.writer(file)
                writer.writerow([timestamp, rtt])
        except Exception as e:
            print(f"Error with client {client_address}: {e}")
            break

    client_socket.close()
    print(f"RTT Server Connection with {client_address} closed.")


def start_server(server_ip, server_port):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((server_ip, server_port))
    server.listen()
    print(f"Server listening on {server_ip}:{server_port}")

    while True:
        client_socket, client_address = server.accept()
        print(f"RTT Connection established with {client_address}")
        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()

if __name__ == "__main__":
    print("Start RTT Server...")
    start_server("192.168.1.106",5005)