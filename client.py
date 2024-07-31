import socket
import sys
import time
import os
from encryption import encrypt_file, generate_aes_key, generate_hmac
from authentication import generate_rsa_key_pair, encrypt_with_public_key

BUFFER_SIZE = 4096
HMAC_SIZE = 64  # Fixed size for HMAC (64 bytes for SHA-256)
PUBLIC_KEY_SIZE = 450  # Public key size in bytes
ENCRYPTED_AES_KEY_SIZE = 256  # Encrypted AES key size in bytes

# Generate RSA key pair for the client
private_key, public_key = generate_rsa_key_pair()

def main(file_path, server_host, server_port):
    # Create a socket and connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Connecting to server...")
    client_socket.connect((server_host, server_port))

    # Send the client's public key to the server
    print("Sending client public key to server...")
    client_socket.sendall(public_key)

    # Receive the server's public key
    server_public_key = client_socket.recv(BUFFER_SIZE)
    print("Received server public key.")

    # Generate a new AES key for file encryption
    aes_key = generate_aes_key()
    print(f"Client AES Key: {aes_key.hex()}")

    # Encrypt the AES key with the server's public key
    encrypted_aes_key = encrypt_with_public_key(server_public_key, aes_key)
    print("Sending encrypted AES key to server...")
    client_socket.sendall(encrypted_aes_key)

    # Get the filename and send it to the server
    filename = os.path.basename(file_path)
    filename_bytes = filename.encode()
    filename_length = len(filename_bytes)
    client_socket.sendall(filename_length.to_bytes(4, byteorder='big'))
    client_socket.sendall(filename_bytes)

    # Encrypt the file using the AES key
    encrypted_data = encrypt_file(file_path, aes_key)
    print(f"Encrypted Data (first 64 bytes): {encrypted_data[:64].hex()}...")

    # Send the size of the encrypted file
    print("Sending encrypted file size...")
    client_socket.sendall(len(encrypted_data).to_bytes(4, byteorder='big'))

    # Send the encrypted file data
    print("Sending encrypted file data...")
    client_socket.sendall(encrypted_data)

    # Generate an HMAC for the encrypted file data
    file_hmac = generate_hmac(aes_key, encrypted_data)
    print(f"Generated HMAC: {file_hmac}")
    print(f"Generated HMAC Length: {len(file_hmac)}")

    # Send the HMAC to the server, ensuring it is HMAC_SIZE bytes long
    print("Sending HMAC to server...")
    hmac_bytes = file_hmac.encode()
    hmac_bytes = hmac_bytes.ljust(HMAC_SIZE, b'\0')  # Pad HMAC to HMAC_SIZE
    print(f"HMAC Bytes: {hmac_bytes}")
    client_socket.sendall(hmac_bytes)

    # Ensure all data is sent before closing the socket
    client_socket.shutdown(socket.SHUT_WR)

    # Short wait to ensure all data is sent
    time.sleep(2)

    print("Closing client socket...")
    client_socket.close()

if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("Usage: python client.py <file_path> <server_host> <server_port>")
        sys.exit(1)

    file_path = sys.argv[1]
    server_host = sys.argv[2]
    server_port = int(sys.argv[3])

    main(file_path, server_host, server_port)
