import socket
import sys
from tools import *
import cProfile

remove_list = ["Received_plaintext.bin"]


class Client:
    def __init__(self, server_address, port):
        self.server_address = server_address
        self.port = port

    def client_download_file(self):
        # Client private and public key.
        c_private_key, c_public_key = generating_RSA_keys()
        password = generating_random_secure_bytes()

        serialized_private_key = serialize_private_key(c_private_key, password)
        # Set up client socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_socket:
            client_socket.connect((self.server_address, self.port))

            # Receiving server public key. Step 2
            server_public_key = client_socket.recv(2048)
            print(f"Client received server pub key:{server_public_key}\n")

            # Sending to server the client public key. Step 3
            client_socket.sendall(serialize_public_key(c_public_key))

            # Received signature of AES key and encrypted AES key. Step 6
            signature_aes = client_socket.recv(256)
            print(f"Received signature AES from server:{signature_aes}\n")
            # Receiving the encrypted AES key from server.
            encrypted_aes_key = client_socket.recv(256)
            print(
                f"Received Encrypted AES key from server:{encrypted_aes_key}\n")

            # Checking the signatur of the encrypted AES key.
            signature_aes_verify = verify_message(deserialize_public_key(server_public_key),
                                                  signature_aes, encrypted_aes_key, client_socket)
            print(f"SIGNATURE AES VERIFIED:{signature_aes_verify}\n")

            # Decrypting the AES key with client private key. Now we have a symmetric key to decrypt ciper text
            aes_key = decrypt_with_rsa(deserialize_private_key(
                serialized_private_key, password), encrypted_aes_key)
            # print(f"AES key decrypted:{aes_key}\n") # Secret no output to terminal!

            # Receiving signed cipher text and the cipher text from server. Step 8
            signature_ciphertext = client_socket.recv(256)
            print(
                f"Received signature ciphertext from server:{signature_aes}\n")

            ciphertext = client_socket.recv(4096)
            print(f"Ciphertext received from server: {ciphertext}\n")

            # Decrypting the cipher text with the AES key.
            plaintext = decrypt_with_aes(aes_key, ciphertext)
            print(f"Decrypted ciphertext \n")

            # Checking the signatur of the ciphertext.
            signature_plaintext_verify = verify_message(
                deserialize_public_key(server_public_key), signature_ciphertext, ciphertext, client_socket)
            print(
                f"SIGNATURE PLAINTEXT VERIFIED:{signature_plaintext_verify}\n")

            # "Download" the plaintext file.
            received_plaintext_name = "received_plaintext.bin"
            with open(received_plaintext_name, 'wb') as file:
                file.write(plaintext)
                print(f"Downloaded: {received_plaintext_name}")

            client_socket.close()

            print("Closed connection to server")


def main():
    if len(sys.argv) != 3:
        print("To connect server type: python3 client.py 'server_ip' 'server_port'")
        sys.exit(1)

    server_address = sys.argv[1]
    port = int(sys.argv[2])

    # pr = cProfile.Profile()
    # pr.enable()
    client = Client(server_address, port)
    client.client_download_file()
    # pr.disable()
    # pr.print_stats()

    sys.exit(0)


if __name__ == "__main__":
    main()
