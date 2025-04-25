# crypto_utils.py

import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a secure encryption key from the master password using PBKDF2.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt(key: bytes, plaintext: str) -> bytes:
    """
    Encrypt plaintext using the derived key.
    """
    fernet = Fernet(key)
    return fernet.encrypt(plaintext.encode())

def decrypt(key: bytes, ciphertext: bytes) -> str:
    """
    Decrypt ciphertext using the derived key.
    """
    fernet = Fernet(key)
    return fernet.decrypt(ciphertext).decode()