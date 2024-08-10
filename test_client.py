import unittest
from unittest.mock import MagicMock, patch
from client import Client
import tkinter as tk
import sys

class TestClientSend(unittest.TestCase):
    def setUp(self):
        self.host = 'localhost'
        self.port = 1060
        self.client = Client(self.host, self.port)

        # Mock the socket object
        self.client.sock = MagicMock()

        # Mock the symmetric key and IV
        self.client.symmetric_key = b'\x01' * 32  # Example key
        self.client.iv = b'\x02' * 16  # Example IV

        # Mock the messages listbox
        self.client.messages = MagicMock()

        # Mock the encryption method to return a known value
        self.client.encrypt_message = MagicMock(return_value=b'fake_encrypted_message')

    @patch('sys.exit')  # Mock sys.exit
    def test_send_message(self, mock_exit):
        # Mock the text input
        text_input = MagicMock()
        text_input.get.return_value = "Test message"
        text_input.delete = MagicMock()

        # Call the send method
        self.client.send(text_input)

        # Verify the textInput's delete method was called
        text_input.delete.assert_called_once_with(0, tk.END)

        # Verify that sendall was called with the mocked encrypted message
        self.client.sock.sendall.assert_called_once_with(b'fake_encrypted_message')

    @patch('sys.exit')  # Mock sys.exit
    def test_send_quit_message(self, mock_exit):
        # Mock the text input for 'QUIT' command
        text_input = MagicMock()
        text_input.get.return_value = "QUIT"
        text_input.delete = MagicMock()

        # Call the send method
        self.client.send(text_input)

        # Verify the textInput's delete method was called
        text_input.delete.assert_called_once_with(0, tk.END)

        # Verify that sendall was called with the appropriate 'QUIT' message
        quit_message = b'fake_encrypted_message'
        self.client.sock.sendall.assert_called_once_with(quit_message)

        # Verify that sys.exit was called
        mock_exit.assert_called_once_with(0)

if __name__ == '__main__':
    unittest.main()
