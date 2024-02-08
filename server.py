import socket
import sys
from tools import *

remove_list = ["server_file.bin"]

LOCALHOST = "127.0.0.1"


class Server:
    def __init__(self, file_data, port):
        self.file_data = file_data
        self.port = port

    def server_serves_file(self):

        # Server private and public key
        s_private_key, s_public_key = generating_RSA_keys()

        # Generating randoms bytes to use as password for serializing private key. Private key won't be send only used local!
        password = generating_random_secure_bytes()

        # Serializing the private key for secure mechanism to store it with hidden password.
        # When using private key i deserialize
        serialized_private_key = serialize_private_key(s_private_key, password)

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
            server_socket.bind((LOCALHOST, self.port))
            server_socket.listen()

            print(f"Server online {LOCALHOST} on port {self.port}")
            while True:
                try:
                    client_socket, client_addr = server_socket.accept()
                    with client_socket:
                        print(f"Connected by {client_addr}")

                        # Sending server public key to client. Step 1
                        client_socket.sendall(
                            serialize_public_key(s_public_key))

                        # Receiving client public key. Step 4
                        client_public_key = client_socket.recv(2048)

                        print(
                            f"Server received client pub key:{client_public_key}\n")

                        # AES key. used for encrypt and decrypt files.
                        aes_key = generating_AES_key()
                        # print(f"AES key generated:{aes_key}\n") # Secret no output to terminal!

                        # Encrypting the AES key with client public key.
                        # Then sending it to client. Before sending it first send signature Step 5
                        encrypted_aes_key = encrypt_with_rsa(
                            deserialize_public_key(client_public_key), aes_key)
                        print(f"Encrypted aes key:{encrypted_aes_key}\n")

                        # Signed the encrypted AES key with server private key and send to client.
                        # Client can verify the sign with server public key.
                        signature_AES = sign_message(
                            deserialize_private_key(
                                serialized_private_key, password), encrypted_aes_key)
                        print(
                            f"Sending Client signature AES:{signature_AES}\n")
                        client_socket.sendall(signature_AES)

                        client_socket.sendall(encrypted_aes_key)

                        # Encrypt the binary file with AES Key and send to client.
                        ciphertext = encrypt_with_aes(aes_key, self.file_data)
                        print(f"Ciphertext sent to client: {ciphertext}\n")

                        # Signed the ciphertext with server private key to send to client.
                        # Client can verify the sign with server public key. And sending the encrypted cipher text. Step 7
                        signature_ciphertext = sign_message(
                            deserialize_private_key(
                                serialized_private_key, password), ciphertext)
                        print(
                            f"Signed ciphertext sent to client: {signature_ciphertext}\n")
                        client_socket.sendall(signature_ciphertext)
                        # Sending the encrypted binary file to client.
                        client_socket.sendall(ciphertext)

                        client_socket.close()

                except KeyboardInterrupt:
                    print("Server is shutting down!")
                    server_socket.close()
                    sys.exit(0)


def main():
    # Generates a server_file.bin
    generate_random_binary_file(20)

    if len(sys.argv) != 3:
        print("To start server type: python3 server.py 'filename or pathname' 'port number (above 1024)'")
        sys.exit(1)

    try:
        file_path = sys.argv[1]
        port = int(sys.argv[2])

        with open(file_path, "rb") as file:
            file_data = file.read()

    except OSError:
        print("Wrong filename or path entered")
        sys.exit(1)

    server = Server(file_data, port)
    server.server_serves_file()


if __name__ == "__main__":
    main()
