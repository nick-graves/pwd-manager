import os
import sqlite3
import bcrypt
from getpass import getpass
from crypto_utils import derive_key, encrypt, decrypt

DB_NAME = "vault.db"
KEYFILE = "keyfile"

def initialize():
    """
    Initializes the vault: sets up DB and authenticates the master password.
    Returns the master password and derived encryption key.
    """
    if not os.path.exists(DB_NAME):
        _create_database()

    if not os.path.exists(KEYFILE):
        return _setup_master_password()
    else:
        return _verify_master_password()

def _create_database():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            username TEXT NOT NULL,
            password BLOB NOT NULL
        );
    ''')
    conn.commit()
    conn.close()

def _setup_master_password():
    print("No master password found. Let's set one up.")
    password = getpass("Create a master password: ")
    confirm = getpass("Confirm master password: ")

    if password != confirm:
        print("Passwords do not match. Try again.")
        return _setup_master_password()

    # Step 1: Generate salt
    salt = bcrypt.gensalt()

    # Step 2: Hash password using salt
    hashed = bcrypt.hashpw(password.encode(), salt)

    # Step 3: Store salt and hashed password
    with open(KEYFILE, 'wb') as f:
        f.write(salt + b'||' + hashed)

    print("Master password set.")

    # Step 4: Derive encryption key from password and salt
    key = derive_key(password, salt=salt)
    return key

def _verify_master_password():
    password = getpass("Enter your master password: ")

    with open(KEYFILE, 'rb') as f:
        salt, hashed = f.read().split(b'||')

    if not bcrypt.checkpw(password.encode(), hashed):
        print("Incorrect master password.")
        exit()

    key = derive_key(password, salt=salt)
    return key

def add_credential(key, url, username, raw_password):
    encrypted = encrypt(key, raw_password)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (url, username, password) VALUES (?, ?, ?)",
                   (url, username, encrypted))
    conn.commit()
    conn.close()
    print("🔐 Credential added.")

def get_credentials(key):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, url, username, password FROM credentials")
    rows = cursor.fetchall()
    conn.close()

    decrypted_rows = []
    for row in rows:
        id_, url, user, enc_pw = row
        try:
            pw = decrypt(key, enc_pw)
        except Exception as e:
            pw = f"Decryption failed: {e}"
        decrypted_rows.append((id_, url, user, pw))

    return decrypted_rows

def delete_credential(cred_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM credentials WHERE id = ?", (cred_id,))
    conn.commit()
    conn.close()
    print("Credential deleted.")
