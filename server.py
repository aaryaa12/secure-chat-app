import threading
import socket
import argparse
import sys
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class Server(threading.Thread):
    def __init__(self, host, port):
        super().__init__()
        self.connections = []
        self.host = host
        self.port = port
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.public_key = self.private_key.public_key()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(5)
        print("Listening at", sock.getsockname())

        while True:
            sc, sockname = sock.accept()
            print(f"Accepted a new connection from {sc.getpeername()} to {sc.getsockname()}")

            client_public_key = serialization.load_pem_public_key(sc.recv(1024))
            sc.sendall(self.public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

            server_socket = ServerSocket(sc, sockname, self, client_public_key)
            server_socket.start()
            self.connections.append(server_socket)
            print("Ready to receive messages from", sc.getpeername())

    def broadcast(self, message, source):
        for connection in self.connections:
            if connection.sockname != source:
                try:
                    connection.send_encrypted(message)
                except ConnectionResetError:
                    self.remove_connection(connection)

    def remove_connection(self, connection):
        if connection in self.connections:
            self.connections.remove(connection)

class ServerSocket(threading.Thread):
    def __init__(self, sc, sockname, server, client_public_key):
        super().__init__()
        self.sc = sc
        self.sockname = sockname
        self.server = server
        self.client_public_key = client_public_key
        self.symmetric_key = os.urandom(32)
        self.iv = os.urandom(16)

    def run(self):
        encrypted_key = self.client_public_key.encrypt(
            self.symmetric_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        self.sc.sendall(encrypted_key + self.iv)

        while True:
            try:
                message = self.sc.recv(1024)
                if message:
                    decrypted_message = self.decrypt_message(message)
                    print(f"{self.sockname} says {decrypted_message}")
                    self.server.broadcast(decrypted_message, self.sockname)
                else:
                    raise ConnectionResetError
            except (ConnectionResetError, ConnectionAbortedError):
                print(f"{self.sockname} has closed the connection")
                self.sc.close()
                self.server.remove_connection(self)
                return

    def encrypt_message(self, message):
        encryptor = Cipher(algorithms.AES(self.symmetric_key), modes.CFB(self.iv)).encryptor()
        return encryptor.update(message.encode('ascii')) + encryptor.finalize()

    def decrypt_message(self, message):
        decryptor = Cipher(algorithms.AES(self.symmetric_key), modes.CFB(self.iv)).decryptor()
        return decryptor.update(message).decode('ascii')

    def send_encrypted(self, message):
        encrypted_message = self.encrypt_message(message)
        self.sc.sendall(encrypted_message)

def exit(server):
    while True:
        ipt = input("")
        if ipt == "q":
            print("Closing all connections...")
            for connection in server.connections:
                connection.sc.close()
            print("Shutting down the server...")
            sys.exit(0)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chatroom server")
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='TCP port (default 1060)')
    args = parser.parse_args()

    server = Server(args.host, args.p)
    server.start()

    exit_thread = threading.Thread(target=exit, args=(server,))
    exit_thread.start()