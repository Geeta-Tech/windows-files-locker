import unittest
from unittest.mock import patch, MagicMock
from cryptography.fernet import Fernet
from module import encrypt_files, decrypt_files  # Replace with your actual module path

class TestFileEncryptionDecryption(unittest.TestCase):

    @patch("builtins.open", new_callable=MagicMock)
    @patch("os.path.isdir", return_value=False)  # Mocking os.path.isdir to always return False (treating paths as files)
    def test_encrypt_files_with_valid_extension(self, mock_isdir, mock_open):
        # Prepare the mock data for encryption
        file_path = "test_file.pdf"
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # Simulate the original file data (content to encrypt)
        original_data = b"Some original file content"
        encrypted_data = fernet.encrypt(original_data)

        # Mock file opening for reading the original data
        mock_open.return_value.__enter__.return_value.read.return_value = original_data
        
        # Mock the write operation
        mock_open.return_value.__enter__.return_value.write = MagicMock()

        # Run the encrypt_files function
        encrypt_files([file_path], key,None)

        # Assert that the file was opened for reading (binary mode)
        mock_open.assert_any_call(file_path, 'rb')  # Assert the file was opened for reading in binary mode

        # Assert that the file was opened for writing (binary mode)
        mock_open.assert_any_call(file_path, 'wb')  # Assert the file was opened for writing in binary mode

        # Assert that the write method was called with encrypted data (check it’s not the original data)
        write_args, _ = mock_open.return_value.__enter__.return_value.write.call_args
        written_data = write_args[0]  # Get the argument passed to write()

        # Check that the written data is not the same as the original data (i.e., encryption happened)
        self.assertNotEqual(written_data, original_data)
        self.assertTrue(written_data)  # Ensure the data is not empty

    @patch("builtins.open", new_callable=MagicMock)
    @patch("os.path.isdir", return_value=False)  # Mocking os.path.isdir to always return False (treating paths as files)
    def test_decrypt_files_with_valid_extension(self, mock_isdir, mock_open):
        # Prepare the mock data for decryption
        file_path = "test_file.pdf"
        key = Fernet.generate_key()
        fernet = Fernet(key)

        # Simulate encrypted data (encrypt some content)
        encrypted_data = fernet.encrypt(b"Some original file content")
        
        # Mock file opening for reading encrypted data
        mock_open.return_value.__enter__.return_value.read.return_value = encrypted_data

        # Decrypt the data using the Fernet instance
        decrypted_data = fernet.decrypt(encrypted_data)

        # Mock the file write operation (encrypted data will be written)
        mock_open.return_value.__enter__.return_value.write = MagicMock()

        # Run the decrypt_files function (which will use our mock for file I/O)
        decrypt_files([file_path], key, None)

        # Assert that the file was opened for reading (binary mode)
        mock_open.assert_any_call(file_path, 'rb')  # Assert the file was opened for reading in binary mode

        # Assert that the file was opened for writing (binary mode)
        mock_open.assert_any_call(file_path, 'wb')  # Assert the file was opened for writing in binary mode

        # Assert that the write method was called with the decrypted data
        mock_open.return_value.__enter__.return_value.write.assert_called_with(decrypted_data)

if __name__ == "__main__":
    unittest.main()
