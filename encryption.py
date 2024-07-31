from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256
import os

BLOCK_SIZE = 16

def pad(data):
    """Add padding to the data to make it a multiple of BLOCK_SIZE."""
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    """Remove padding from the data."""
    padding_length = data[-1]
    if padding_length > BLOCK_SIZE:
        raise ValueError("Invalid padding")
    return data[:-padding_length]

def generate_aes_key():
    """Generate a secure random 256-bit AES key."""
    return get_random_bytes(32)  # 256-bit key

def encrypt_file(file_path, key):
    """Encrypt a file with the given AES key."""
    cipher = AES.new(key, AES.MODE_CBC)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext = cipher.encrypt(pad(plaintext))
    return cipher.iv + ciphertext

def decrypt_file(encrypted_data, key):
    """Decrypt a file with the given AES key."""
    iv = encrypted_data[:BLOCK_SIZE]
    ciphertext = encrypted_data[BLOCK_SIZE:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))
    return plaintext

def generate_hmac(key, data):
    """Generate an HMAC for the given data using the provided key."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    return h.hexdigest()

def verify_hmac(key, data, hmac):
    """Verify the HMAC for the given data using the provided key."""
    h = HMAC.new(key, digestmod=SHA256)
    h.update(data)
    try:
        h.hexverify(hmac)
        return True
    except ValueError:
        return False
