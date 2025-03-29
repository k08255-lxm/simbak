import os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64
import secrets # For generating salts

# Use a consistent key derived from the Flask SECRET_KEY or a dedicated env variable
# WARNING: Changing the base key (SECRET_KEY) will make previously encrypted data unreadable!
# Store the encryption key securely, ideally not directly in code.
# For simplicity here, we derive it from SECRET_KEY. A dedicated env var is better.

_fernet_instance = None
_salt = None # Store salt alongside encrypted data ideally, or derive consistently

def _get_encryption_key(app_secret_key, salt):
    """Derives a suitable encryption key from the app's secret key using PBKDF2."""
    if not app_secret_key:
        raise ValueError("SECRET_KEY is not set in the Flask app configuration.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32, # Fernet key size
        salt=salt,
        iterations=390000, # Adjust iterations as needed (higher is slower but more secure)
        backend=default_backend()
    )
    # Use base64 encoding for URL-safe key
    key = base64.urlsafe_b64encode(kdf.derive(app_secret_key.encode()))
    return key

def _initialize_fernet(app_secret_key):
    """Initializes the Fernet instance using a derived key."""
    global _fernet_instance, _salt
    if _fernet_instance is None:
        # Generate or load a persistent salt. For simplicity, generate if not present.
        # In production, this salt should be stored securely and consistently.
        # Maybe store it in the instance folder?
        # For now, we'll just use a fixed string, which is NOT ideal for security.
        # A better approach: generate once, store in config/db.
        _salt = b'simbak_persistent_salt' # BAD PRACTICE - REPLACE with stored random salt

        derived_key = _get_encryption_key(app_secret_key, _salt)
        _fernet_instance = Fernet(derived_key)

def encrypt_data(data: str, app_secret_key: str) -> str:
    """Encrypts a string using Fernet."""
    if not data:
        return ""
    _initialize_fernet(app_secret_key)
    if _fernet_instance:
        encrypted_bytes = _fernet_instance.encrypt(data.encode())
        # Return as string for database storage
        return encrypted_bytes.decode()
    else:
        raise RuntimeError("Fernet encryption not initialized.")

def decrypt_data(encrypted_data: str, app_secret_key: str) -> str:
    """Decrypts a string using Fernet."""
    if not encrypted_data:
        return ""
    _initialize_fernet(app_secret_key)
    if _fernet_instance:
        try:
            decrypted_bytes = _fernet_instance.decrypt(encrypted_data.encode())
            return decrypted_bytes.decode()
        except Exception as e:
            # Handle potential decryption errors (e.g., wrong key, corrupted data)
            print(f"Error decrypting data: {e}")
            # Depending on context, either raise, return None, or return a placeholder
            return "[DECRYPTION FAILED]"
    else:
        raise RuntimeError("Fernet encryption not initialized.")

def generate_api_key(length=40):
    """Generates a secure random API key."""
    return secrets.token_urlsafe(length)

def generate_salt(length=16):
    """Generates a secure random salt."""
    return secrets.token_hex(length)

def hash_api_key(api_key):
    """Hashes an API key using SHA-256 for storage."""
    # Use a strong hashing algorithm. SHA-256 is common.
    # Do NOT store the raw API key. Store its hash.
    # When a client authenticates, hash the provided key and compare hashes.
    hasher = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hasher.update(api_key.encode())
    return hasher.finalize().hex()

def verify_api_key(stored_hash, provided_key):
    """Verifies a provided API key against a stored hash."""
    return stored_hash == hash_api_key(provided_key)
