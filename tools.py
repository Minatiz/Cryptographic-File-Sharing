# library used and tools.
import sys
import secrets
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def generating_RSA_keys():
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/
    # Use public exponent and key_size ^
    private_key = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
    # deriving public key from the private key
    public_key = private_key.public_key()
    return private_key, public_key


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


def serialize_public_key(public_key):
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
    # Serializing public key before sending it. (PEM) Wil make it readable and not as object
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def deserialize_public_key(public_key):
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#key-serialization
    # Deserializing the public key for using for encryption.
    return serialization.load_pem_public_key(public_key)


def serialize_private_key(private_key, password_in_bytes):
    # Same as how public just here private bytes and for private key
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password=password_in_bytes)
    )


def deserialize_private_key(private_key, password_in_bytes):
    return serialization.load_pem_private_key(private_key, password=password_in_bytes)


def generating_AES_key():
    return secrets.token_bytes(32)  # 32 bytes, 256 bits length key


# Used for generating random password for serializing private keys
def generating_random_secure_bytes():
    return secrets.token_bytes(16)


def encrypt_with_aes(key, data):
    # Encrypting with Counter Mode (CTR). Padding not needed for this mode: https://cryptography.io/en/latest/hazmat/primitives/symmetric-encryption/#cryptography.hazmat.primitives.ciphers.modes.CTR
    iv = secrets.token_bytes(16)  # Block size
    cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext


def decrypt_with_aes(aes_key, data):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_data


def sign_message(s_private_key, data):
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#signing
    # Signing data/message
    signature = s_private_key.sign(data, padding.PSS(mgf=padding.MGF1(
        hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
    return signature


def verify_message(s_public_key, signature, data, client_socket):
    # https://cryptography.io/en/latest/hazmat/primitives/asymmetric/rsa/#verification
    # Verify if the signature is correct.
    try:
        s_public_key.verify(signature, data, padding.PSS(mgf=padding.MGF1(
            hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
        return True
    except Exception:
        client_socket.close()
        print(f"Signature verification failed on {signature}")
        sys.exit(1)


def generate_random_binary_file(size_bytes):
    with open("server_file.bin", 'wb') as file:
        random_data = secrets.token_bytes(size_bytes)
        file.write(random_data)
