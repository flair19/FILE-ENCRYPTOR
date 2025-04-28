from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Function to generate a secret key based on a password
def generate_secret_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        salt=salt,
        length=16,  # AES-128 requires a 16-byte key
        iterations=100000,
        backend=default_backend()
    )
    secret_key = kdf.derive(password.encode('utf-8'))
    return secret_key

# Function to encrypt the file
def encrypt_file(file_path, password, output_file):
    # Generate a random salt (this should be stored for later key derivation)
    salt = os.urandom(16)
    
    # Generate the secret key from the password and salt
    secret_key = generate_secret_key(password, salt)
    
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Create the cipher object using AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Read the plaintext from the file
    with open(file_path, 'rb') as file:
        data = file.read()

    # Apply padding to the data to be encrypted
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Encrypt the data
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Save the salt, IV, and encrypted data to a new file
    with open(output_file, 'wb') as enc_file:
        enc_file.write(salt)  # Save the salt at the start of the file
        enc_file.write(iv)  # Save IV after the salt
        enc_file.write(encrypted_data)  # Write the encrypted content

    print(f"File encrypted successfully and saved to {output_file}")

# Function to decrypt the file
def decrypt_file(encrypted_file_path, password, output_file):
    # Read the encrypted file to get the salt, IV, and encrypted content
    with open(encrypted_file_path, 'rb') as enc_file:
        salt = enc_file.read(16)  # Extract salt (first 16 bytes)
        iv = enc_file.read(16)  # Extract IV (next 16 bytes)
        encrypted_data = enc_file.read()  # The rest is the encrypted data

    # Generate the secret key from the password and salt
    secret_key = generate_secret_key(password, salt)

    # Create the cipher object using AES algorithm and CBC mode
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the data
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Remove padding from the decrypted data
    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(decrypted_data) + unpadder.finalize()

    # Save the decrypted content to a new file
    with open(output_file, 'wb') as dec_file:
        dec_file.write(original_data)

    print(f"File decrypted successfully and saved to {output_file}")

# Main function to handle user input
def main():
    print("Welcome to the File Encryption/Decryption Program!")

    choice = input("Do you want to encrypt or decrypt a file? (encrypt/decrypt): ").strip().lower()

    if choice == 'encrypt':
        file_path = input("Enter the path of the text file to encrypt: ").strip()
        password = input("Enter a password to generate the secret key: ").strip()
        output_file = input("Enter the name of the output encrypted file: ").strip()
        encrypt_file(file_path, password, output_file)

    elif choice == 'decrypt':
        encrypted_file_path = input("Enter the path of the encrypted file to decrypt: ").strip()
        password = input("Enter the password used to encrypt the file: ").strip()
        output_file = input("Enter the name of the output decrypted file: ").strip()
        decrypt_file(encrypted_file_path, password, output_file)

    else:
        print("Invalid choice. Please choose 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()
