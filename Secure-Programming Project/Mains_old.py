from Crypto.Cipher import AES #
from Crypto.Protocol.KDF import PBKDF2 #
from Crypto.Random import get_random_bytes #
import base64 # For encryption mechanisms

import bcrypt # For password hashing

import sqlite3 # For secure storage

import os # For secure storage location to be OS based

def get_database_path():
    # Get the LOCALAPPDATA path
    appdata_path = os.getenv("LOCALAPPDATA")
    # Create a directory for the password manager
    secure_folder = os.path.join(appdata_path, "MyPasswordManager")
    os.makedirs(secure_folder, exist_ok=True)  # Ensure the folder exists
    return os.path.join(secure_folder, "password_manager.db")

def create_table():
    db_path = get_database_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials (
                        id INTEGER PRIMARY KEY, 
                        username TEXT, 
                        service TEXT, 
                        password TEXT
                      )''')
    conn.commit()
    conn.close()
    print("Database created at: " + db_path)

def add_credential(username, service, encrypted_password):
    db_path = get_database_path()
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (username, service, password) VALUES (?, ?, ?)",
                   (username, service, encrypted_password))
    conn.commit()
    conn.close()
    print("Database stored at: " + db_path)

# Hashing password using bcrypt
def hash_master_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())

# Checking password
def verify_master_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed)

# Constants for PBKDF2
SALT_LENGTH = 16
KEY_LENGTH = 32  # 256-bit key for AES
PBKDF2_ITERATIONS = 100_000

# Derive a secure key from the master password
def derive_key(master_password, salt):
    return PBKDF2(master_password, salt, dkLen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

# Encrypt a plaintext password
def encrypt_password(password, master_password):
    # Generate a random salt and derive the encryption key
    salt = get_random_bytes(SALT_LENGTH)
    key = derive_key(master_password, salt)
    
    # Create a cipher object with a random nonce
    cipher = AES.new(key, AES.MODE_GCM)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(password.encode())

    # Concatenate salt, nonce, tag, and ciphertext for storage
    encrypted_data = salt + nonce + tag + ciphertext
    return base64.b64encode(encrypted_data).decode()

# Decrypt an encrypted password
def decrypt_password(encrypted, master_password):
    # Decode and parse the stored data
    data = base64.b64decode(encrypted)
    salt = data[:SALT_LENGTH]
    nonce = data[SALT_LENGTH:SALT_LENGTH + 16]
    tag = data[SALT_LENGTH + 16:SALT_LENGTH + 32]
    ciphertext = data[SALT_LENGTH + 32:]

    # Derive the encryption key using the same salt
    key = derive_key(master_password, salt)

    # Decrypt and verify the ciphertext
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()

def main():
    p = "nope"
    p_hashed_decoded = hash_master_password(p).decode()
    print("Pass: " + p)
    print("Decoded Hashed Pass: " + p_hashed_decoded)

    m = "yes"
    m_hashed_decoded = hash_master_password(m).decode()
    print("Masterpass: " + m)
    print("Decoded Hashed Masterpass: " + m_hashed_decoded)


    e_p = encrypt_password(p, m)
    print("Encrypted pass: " + e_p)

    d_p = decrypt_password(e_p, m)
    print("Decrypted pass: " + d_p)

    create_table()
    add_credential("John", "yt", e_p)

main()