# File Encryption/Decryption Program

This program allows you to **encrypt** and **decrypt** text files using a secret key derived from a password. The program uses the **AES** encryption algorithm in **CBC mode** (Cipher Block Chaining) and the **PBKDF2** key derivation function to securely generate keys from passwords. The encryption key and the initialization vector (IV) are stored along with the encrypted file, so the file can be decrypted using the same password.

---

## Features

- **Password-Based Encryption**: The program generates an AES key based on the password provided by the user, using the PBKDF2 key derivation function with a random salt.
- **Salt and IV Storage**: The salt (used to generate the secret key) and IV (used for AES encryption) are stored along with the encrypted file to enable proper decryption.
- **File Encryption & Decryption**: Encrypt and decrypt text files easily by providing the correct password.
- **Secure Key Generation**: The key used for encryption and decryption is derived from the password, which is never stored directly. The salt is saved to allow key regeneration.

---

## Requirements

- Python 3.x
- **cryptography** library

### Installing Dependencies

You can install the required `cryptography` library using pip:

```bash
pip install cryptography
