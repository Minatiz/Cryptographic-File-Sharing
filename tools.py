# library used and tools.
import sys
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# Use public exponent and key_size with the standard info, link below for more info.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
def generating_RSA_keys():
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
    # deriving public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key


# Encrypting rsa key with OAEP padding and with hash function SHA256
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#encryption
def encrypt_with_rsa(public_key, data):
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# Decrypting the rsa key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#decryption
def decrypt_with_rsa(private_key, cipher_text):
    plaintext = private_key.decrypt(
        cipher_text,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


# Serializing public key before sending it. (PEM) Wil make it readable and not as object
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
def serialize_public_key(public_key):
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


# Deserializing the public key for using for encryption.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-loading
def deserialize_public_key(public_key):
    return serialization.load_pem_public_key(public_key)


# Same as how public just here private bytes and for private key. Also adding password to encrypt the private key
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
def serialize_private_key(private_key, password_in_bytes):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password=password_in_bytes)
    )


# Deserializing the private key with password
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-loading
def deserialize_private_key(private_key, password_in_bytes):
    return serialization.load_pem_private_key(private_key, password=password_in_bytes)


# Generating secure bytes, using it for generating AES key.
def generating_AES_key():
    return secrets.token_bytes(32)  # 32 bytes, 256 bits length key


# Used for generating random password for serializing private keys
def generating_random_secure_bytes():
    return secrets.token_bytes(16)


# Encrypting the AES key with counter mode
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher
def encrypt_with_aes(key, data):
    # Padding not needed for this mode: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CTR
    iv = secrets.token_bytes(16)  # Block size 128 bits
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext


# Decrypting the AES key, the reverse of encrypter and slicing data.
# https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.Cipher.decryptor
def decrypt_with_aes(aes_key, data):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data


# Signing data/message for server before sending to client.
# With PSS padding and SHA256 hashed. Salt length as long as possible to avoid collision and rainbow attacks.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
def sign_message(s_private_key, data):
    signature = s_private_key.sign(data, padding.PSS(mgf=padding.MGF1(
        hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature


# Verify if the signature is correct. To authenticate that server is the sender.
# https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#verification
def verify_message(s_public_key, signature, data, client_socket):
    try:
        s_public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    # If not verified exit and close the program, we terminate the process due to tampered data
    except Exception:
        client_socket.close()
        print(f"Signature verification failed on {signature}")
        print(f"Data tampered exiting! (Received file from unknown host likely)")
        sys.exit(1)


# Generating random binary file for the server to serve.
def generate_random_binary_file(size_bytes):
    with open("server_file.bin", 'wb') as file:
        random_data = secrets.token_bytes(size_bytes)
        file.write(random_data)
