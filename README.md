# Windows File Encryption and Decryption

A Python-based tool to easily encrypt and decrypt files with strong encryption. This project is designed to help users protect their sensitive files by encrypting them and then securely decrypting them when needed. 

## Features
- Encrypt files with a passphrase (basic encryption).
- Decrypt encrypted files back to their original form.
- Supports valid file extensions for encryption and decryption operations.

## Installation

### Requirements
- Python 3.7+ 
- Cryptography library (for encryption/decryption)

You can install the required dependencies by running:

```bash
pip install -r requirements.txt
```

## Dependencies
- `cryptography`: A library to handle encryption and decryption.


## Usage

### Encryption

- To encrypt a file, use the `encrypt_files` function. The function will encrypt one or more files and save the encrypted version.

`Example:`

```python
from module_name import encrypt_files

file_path = 'path/to/file1.pdf'  # file to encrypt
key = b'your-secret-key-here'  # key for encryption (must be 32 bytes)
# Automatically generated be encrypt_files
encrypt_files(file_path, key)
```

### Decryption

- To encrypt a file, use the `decrypt_files` function. The function will decrypt one or more files and save the decrypted version.

`Example:`

```python
from module_name import decrypt_files

file_path = 'path/to/file1.pdf'  # file to decrypt
key = b'your-secret-key-here'  # key for decryption (must be 32 bytes)
# Automatically generated be decrypt_files
decrypt_files(file_path, key)
```

## File Extension Support
- This tool supports encryption and decryption only for files with the following extensions:

     - `txt`
     - `pdf`
     - `docx`
     - `jpg`
     - `mp4`
     - `mkv`
- Files with unsupported extensions will not be processed.


# Contributing
>We welcome contributions to this project!

Here are ways you can help:

- Report bugs or request features via GitHub Issues.
- Fork the repository and submit a pull request for improvements or new features.

## How to Contribute:
1. Fork this repository.
2. Create a new branch for your feature or fix.
3. Make your changes.
4. Test your changes thoroughly.
5. Submit a pull request describing your changes.
6. For large changes, please open an issue first to discuss it.

# License
> This project is licensed under the MIT License. See the [LICENSE](https://github.com/Geeta-Tech/windows-files-locker/blob/main/LICENSE) file for more details.

# Contact
>For any questions or suggestions, please contact the project maintainer at 

[email](mailto:geetatech.dev@gmail.com)

