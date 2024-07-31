import socket
from encryption import decrypt_file, generate_hmac, verify_hmac
from authentication import decrypt_with_private_key, generate_rsa_key_pair

SERVER_HOST = '0.0.0.0'
SERVER_PORT = 5001
BUFFER_SIZE = 4096
HMAC_SIZE = 64  # Fixed size for HMAC (64 bytes for SHA-256)
PUBLIC_KEY_SIZE = 450  # Public key size in bytes
ENCRYPTED_AES_KEY_SIZE = 256  # Encrypted AES key size in bytes

# Generate RSA key pair for the server
private_key, public_key = generate_rsa_key_pair()

def recv_all(sock, length):
    """Receive exactly `length` bytes from the socket."""
    data = b''
    while len(data) < length:
        more = sock.recv(length - len(data))
        if not more:
            raise EOFError(f'Expected {length} bytes but only received {len(data)} bytes before the socket closed')
        data += more
    return data

def handle_client(client_socket):
    try:
        # Receive the client's public key
        print("Receiving client public key...")
        client_public_key = recv_all(client_socket, PUBLIC_KEY_SIZE)
        print("Received client public key.")

        # Send the server's public key to the client
        print("Sending server public key to client...")
        client_socket.sendall(public_key)

        # Receive the encrypted AES key from the client and decrypt it
        print("Receiving encrypted AES key...")
        encrypted_aes_key = recv_all(client_socket, ENCRYPTED_AES_KEY_SIZE)
        aes_key = decrypt_with_private_key(private_key, encrypted_aes_key)
        print(f"Server AES Key: {aes_key.hex()}")

        # Receive the filename length and filename
        filename_length = int.from_bytes(recv_all(client_socket, 4), byteorder='big')
        filename = recv_all(client_socket, filename_length).decode()
        print(f"Receiving file: {filename}")

        # Receive the encrypted file size
        print("Receiving encrypted file size...")
        encrypted_file_size = int.from_bytes(recv_all(client_socket, 4), byteorder='big')
        print(f"Encrypted file size: {encrypted_file_size}")

        # Receive the encrypted file data
        print("Receiving encrypted file data...")
        encrypted_file_data = recv_all(client_socket, encrypted_file_size)
        print(f"Encrypted Data (first 64 bytes): {encrypted_file_data[:64].hex()}...")

        # Receive the HMAC
        print("Receiving HMAC...")
        received_hmac = recv_all(client_socket, HMAC_SIZE)
        print(f"Raw Received HMAC Bytes: {received_hmac}")
        received_hmac = received_hmac.decode().strip('\0')
        print(f"Received HMAC Length: {len(received_hmac)}")
        print(f"Received HMAC: {received_hmac}")

        # Generate HMAC for verification
        print("Generating HMAC for verification...")
        generated_hmac = generate_hmac(aes_key, encrypted_file_data)
        print(f"Generated HMAC: {generated_hmac}")

        # Verify the HMAC
        print("Verifying HMAC...")
        if verify_hmac(aes_key, encrypted_file_data, received_hmac):
            print("HMAC verification succeeded.")
            decrypted_data = decrypt_file(encrypted_file_data, aes_key)
            with open(filename, "wb") as f:
                f.write(decrypted_data)
            print("File received and verified successfully.")
        else:
            print("HMAC verification failed.")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        print("Closing client socket...")
        client_socket.close()

def main():
    # Create a socket and bind it to the server address and port
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, SERVER_PORT))
    server_socket.listen(5)
    print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}...")

    try:
        while True:
            # Accept a new client connection
            client_socket, addr = server_socket.accept()
            print(f"Accepted connection from {addr}")
            handle_client(client_socket)
    except KeyboardInterrupt:
        print("Shutting down server.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
