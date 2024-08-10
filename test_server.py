import unittest
from server import ServerSocket
from unittest.mock import MagicMock
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class TestServerSocket(unittest.TestCase):
    def setUp(self):
        self.mock_socket = MagicMock()
        self.sockname = ('localhost', 1060)
        self.server = MagicMock()

        # Generate a random symmetric key and IV for testing
        self.symmetric_key = os.urandom(32)
        self.iv = os.urandom(16)

        # Create an instance of ServerSocket for testing
        self.server_socket = ServerSocket(self.mock_socket, self.sockname, self.server, None)
        self.server_socket.symmetric_key = self.symmetric_key
        self.server_socket.iv = self.iv

    # Existing test functions
    def test_encrypt_message(self):
        test_message = "Hello, World!"
        encrypted_message = self.server_socket.encrypt_message(test_message)
        decryptor = Cipher(algorithms.AES(self.symmetric_key), modes.CFB(self.iv)).decryptor()
        decrypted_message = decryptor.update(encrypted_message).decode('ascii')
        self.assertEqual(decrypted_message, test_message)

    def test_decrypt_message(self):
        test_message = "Hello, World!"
        encrypted_message = self.server_socket.encrypt_message(test_message)
        decrypted_message = self.server_socket.decrypt_message(encrypted_message)
        self.assertEqual(decrypted_message, test_message)

    # New function to validate message
    def validate_message(self, message):
        if not message:
            return False
        if len(message) > 256:  # Example limit
            return False
        return True

    def test_validate_message(self):
        self.assertTrue(self.validate_message("This is a valid message"))
        self.assertFalse(self.validate_message(""))  # Empty message
        self.assertFalse(self.validate_message("x" * 257))  # Exceeds length

if __name__ == '__main__':
    unittest.main()
