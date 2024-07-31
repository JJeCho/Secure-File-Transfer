# Secure File Transfer

## Overview

Secure File Transfer is a project designed to securely transfer files between a client and server using modern cryptographic techniques. The project ensures the confidentiality, integrity, and authenticity of the transferred files through encryption, key management, and HMAC verification.

## Features

- **AES-256 Encryption**: Files are encrypted using AES-256 in CBC mode.
- **RSA Encryption**: AES keys are securely exchanged using RSA encryption.
- **HMAC Verification**: Integrity and authenticity of the files are verified using HMAC-SHA256.
- **Secure Key Management**: RSA key pairs are generated and securely managed for each session.

## Project Structure

- **client.py**: The client application that encrypts and sends files to the server.
- **server.py**: The server application that receives, decrypts, and verifies files from the client.
- **encryption.py**: Contains functions for AES encryption/decryption and HMAC generation/verification.
- **authentication.py**: Contains functions for RSA key generation, encryption, and decryption.

## Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/jjecho55/secure-file-transfer.git
    cd secure-file-transfer
    ```

2. **Create a virtual environment and activate it**:
    ```sh
    python3 -m venv venv
    source venv/bin/activate   # On Windows: venv\Scripts\activate
    ```

3. **Install the required packages**:
    ```sh
    pip install -r requirements.txt
    ```

## Usage

### Running the Server

1. **Start the server**:
    ```sh
    python server.py
    ```

2. The server will start listening on `0.0.0.0:5001`.

### Running the Client

1. **Send a file from the client**:
    ```sh
    python client.py <file_path> <server_host> <server_port>
    ```

    - `<file_path>`: Path to the file you want to send.
    - `<server_host>`: The server's hostname or IP address.
    - `<server_port>`: The port on which the server is listening (default is `5001`).

### Example

1. **Start the server**:
    ```sh
    python server.py
    ```

2. **Send a file from the client**:
    ```sh
    python client.py example.txt 127.0.0.1 5001
    ```

## Code Overview

### `client.py`

- Connects to the server.
- Sends the client's RSA public key.
- Receives the server's RSA public key.
- Generates an AES key and encrypts it with the server's public key.
- Encrypts the file using AES-256.
- Sends the encrypted AES key, the encrypted file, and the HMAC to the server.

### `server.py`

- Listens for incoming client connections.
- Receives the client's RSA public key.
- Sends the server's RSA public key.
- Receives and decrypts the AES key using the server's private key.
- Receives and decrypts the file using AES-256.
- Verifies the HMAC to ensure file integrity and authenticity.

### `encryption.py`

- **`pad(data)`**: Adds padding to the data to make it a multiple of the block size.
- **`unpad(data)`**: Removes padding from the data.
- **`generate_aes_key()`**: Generates a secure 256-bit AES key.
- **`encrypt_file(file_path, key)`**: Encrypts a file using AES-256.
- **`decrypt_file(encrypted_data, key)`**: Decrypts a file using AES-256.
- **`generate_hmac(key, data)`**: Generates an HMAC for the given data.
- **`verify_hmac(key, data, hmac)`**: Verifies the HMAC for the given data.

### `authentication.py`

- **`generate_rsa_key_pair()`**: Generates a secure RSA key pair (2048 bits).
- **`encrypt_with_public_key(public_key, data)`**: Encrypts data with the provided RSA public key.
- **`decrypt_with_private_key(private_key, encrypted_data)`**: Decrypts data with the provided RSA private key.

## Security Considerations

- Ensure the secure storage and management of RSA private keys.
- Regularly audit and update cryptographic practices to align with the latest security standards.
- Consider using hardware security modules (HSM) for key management in a production environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.


