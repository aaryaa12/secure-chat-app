import threading
import socket
import argparse
import sys
import tkinter as tk
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

class Send(threading.Thread):
    def __init__(self, sock, name, symmetric_key, iv):
        super().__init__()
        self.sock = sock
        self.name = name
        self.symmetric_key = symmetric_key
        self.iv = iv

    def run(self):
        while True:
            print('{}: '.format(self.name), end='')
            sys.stdout.flush()
            message = sys.stdin.readline()[:-1]

            if message == "QUIT":
                self.sock.sendall(self.encrypt_message('Server: {} has left the chat.'.format(self.name)))
                break
            else:
                self.sock.sendall(self.encrypt_message('{}: {}'.format(self.name, message)))

        print('\nQuitting...')
        self.sock.close()
        sys.exit(0)

    def encrypt_message(self, message):
        encryptor = Cipher(algorithms.AES(self.symmetric_key), modes.CFB(self.iv)).encryptor()
        return encryptor.update(message.encode('ascii')) + encryptor.finalize()

class Receive(threading.Thread):
    def __init__(self, sock, name, symmetric_key, iv):
        super().__init__()
        self.sock = sock
        self.name = name
        self.symmetric_key = symmetric_key
        self.iv = iv
        self.messages = None

    def run(self):
        while True:
            try:
                message = self.sock.recv(1024)
                if message:
                    decrypted_message = self.decrypt_message(message)
                    if self.messages:
                        self.messages.insert(tk.END, decrypted_message)
                        print('\r{}\n{}: '.format(decrypted_message, self.name), end='')
                    else:
                        print('\r{}\n{}: '.format(decrypted_message, self.name), end='')
                else:
                    raise ConnectionResetError
            except (ConnectionResetError, ConnectionAbortedError):
                print('\nConnection to server lost!')
                print('\nQuitting...')
                self.sock.close()
                sys.exit(0)

    def decrypt_message(self, message):
        decryptor = Cipher(algorithms.AES(self.symmetric_key), modes.CFB(self.iv)).decryptor()
        return decryptor.update(message).decode('ascii')

class Client:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.name = None
        self.messages = None
        self.symmetric_key = None
        self.iv = None

    def start(self):
        print('Trying to connect to {}:{}...'.format(self.host, self.port))
        self.sock.connect((self.host, self.port))
        print('Successfully connected to {}:{}'.format(self.host, self.port))
        print()
        self.name = input('Your name: ')
        print()
        print('Welcome, {}! Getting ready to send and receive messages...'.format(self.name))

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        self.sock.sendall(public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

        server_public_key = serialization.load_pem_public_key(self.sock.recv(1024))
        encrypted_key_iv = self.sock.recv(256 + 16)
        self.symmetric_key = private_key.decrypt(
            encrypted_key_iv[:256],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        self.iv = encrypted_key_iv[256:]

        send = Send(self.sock, self.name, self.symmetric_key, self.iv)
        receive = Receive(self.sock, self.name, self.symmetric_key, self.iv)

        send.start()
        receive.start()

        self.sock.sendall(send.encrypt_message('Server: {} has joined the chat. Say hi!'.format(self.name)))
        print("\rReady! Leave the chatroom anytime by typing 'QUIT'\n")
        print('{}: '.format(self.name), end='')

        return receive

    def send(self, textInput):
        message = textInput.get()
        textInput.delete(0, tk.END)
        self.messages.insert(tk.END, '{}: {}'.format(self.name, message))

        if message == "QUIT":
            self.sock.sendall(self.encrypt_message('Server: {} has left the chat room'.format(self.name)))
            print('\nQuitting...')
            self.sock.close()
            sys.exit(0)
        else:
            self.sock.sendall(self.encrypt_message('{}: {}'.format(self.name, message)))

    def encrypt_message(self, message):
        encryptor = Cipher(algorithms.AES(self.symmetric_key), modes.CFB(self.iv)).encryptor()
        return encryptor.update(message.encode('ascii')) + encryptor.finalize()

def main(host, port):
    client = Client(host, port)
    receive = client.start()

    window = tk.Tk()
    window.title("Chatroom")

    fromMessage = tk.Frame(master=window)
    scrollBar = tk.Scrollbar(master=fromMessage)
    messages = tk.Listbox(master=fromMessage, yscrollcommand=scrollBar.set)
    scrollBar.pack(side=tk.RIGHT, fill=tk.Y, expand=False)
    messages.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    client.messages = messages
    receive.messages = messages

    fromMessage.grid(row=0, column=0, columnspan=2, sticky="nsew")
    fromEntry = tk.Frame(master=window)
    textInput = tk.Entry(master=fromEntry)
    textInput.pack(fill=tk.BOTH, expand=True)
    textInput.bind("<Return>", lambda x: client.send(textInput))
    textInput.insert(0, "Write your message here... ")

    btnSend = tk.Button(
        master=window,
        text='Send',
        command=lambda: client.send(textInput)
    )

    fromEntry.grid(row=1, column=0, padx=10, sticky="ew")
    btnSend.grid(row=1, column=1, pady=10, sticky="ew")

    window.rowconfigure(0, minsize=500, weight=1)
    window.rowconfigure(1, minsize=50, weight=0)
    window.columnconfigure(0, minsize=500, weight=1)
    window.columnconfigure(1, minsize=200, weight=0)

    window.mainloop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Chatroom server")
    parser.add_argument('host', help='Interface the server listens at')
    parser.add_argument('-p', metavar='PORT', type=int, default=1060, help='TCP port (default 1060)')
    args = parser.parse_args()
    main(args.host, args.p)