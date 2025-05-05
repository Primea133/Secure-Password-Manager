from Crypto.Protocol.KDF import PBKDF2 #
from Crypto.Random import get_random_bytes #
from Crypto.Cipher import AES #
import base64 # For encryption mechanisms

import bcrypt # For password hashing

# PBKDF2 parameters
SALT_LENGTH = 16
KEY_LENGTH = 32
PBKDF2_ITERATIONS = 100_000

# Derive a secure key from the master password
def derive_key(master_password, salt):
    return PBKDF2(master_password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

# Encrypt a plaintext password
def encrypt_password(password, master_password):
    # Generate a random salt and derive the encryption key
    salt = get_random_bytes(SALT_LENGTH)
    key = derive_key(master_password, salt)
    
    # Create a cipher object with a iv
    cipher = AES.new(key, AES.MODE_GCM)
    iv = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())

    # Concatenate salt, iv, tag, and ciphertext for storage
    encrypted_data = salt + iv + tag + ciphertext
    return base64.b64encode(encrypted_data).decode()

# Decrypt an encrypted password
def decrypt_password(encrypted, master_password):
    # Decode and parse the stored data
    data = base64.b64decode(encrypted)
    salt = data[:SALT_LENGTH]
    iv = data[SALT_LENGTH:SALT_LENGTH + 16]
    tag = data[SALT_LENGTH + 16:SALT_LENGTH + 32]
    ciphertext = data[SALT_LENGTH + 32:]

    # Derive the encryption key using the same salt
    key = derive_key(master_password, salt)

    # Decrypt and verify the ciphertext
    cipher = AES.new(key, AES.MODE_GCM, nonce=iv)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

# Hashing password using bcrypt
def hash_master_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Checking password
def verify_master_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)