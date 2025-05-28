import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from PIL import Image
import io

# Key derivation function
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Encrypt image
def encrypt_image(image_path: str, password: str) -> bytes:
    with open(image_path, 'rb') as f:
        image_data = f.read()

    salt = os.urandom(16)
    iv = os.urandom(12)
    key = derive_key(password, salt)

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(image_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return salt + iv + encryptor.tag + ciphertext

# Decrypt image
def decrypt_image(encrypted_data: bytes, password: str) -> bytes:
    salt = encrypted_data[:16]
    iv = encrypted_data[16:28]
    tag = encrypted_data[28:44]
    ciphertext = encrypted_data[44:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    image_data = unpadder.update(padded_data) + unpadder.finalize()

    return image_data

# Save decrypted image
def save_image(image_data: bytes, output_path: str):
    image = Image.open(io.BytesIO(image_data))
    image.save(output_path)

# Example usage
if __name__ == "__main__":
    password = "strong_password"
    encrypted = encrypt_image("input_image.jpg", password)
    decrypted = decrypt_image(encrypted, password)
    save_image(decrypted, "decrypted_image.jpg")
