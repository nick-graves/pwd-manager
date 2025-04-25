# LocalVault - Security & Implementation Notes

This document provides a breakdown of the key cryptographic mechanisms used in the **LocalVault** password manager, explaining how each component contributes to confidentiality, integrity, and resistance to attacks.

---

## Master Password Authentication

### Password Hashing
- **Algorithm**: `bcrypt`
- **Why?** Bcrypt is intentionally slow, resistant to GPU brute-force attacks, and includes built-in salt handling.
- **Usage**:
  - User inputs a master password on setup
  - A random salt is generated using `bcrypt.gensalt()`
  - The password is hashed with this salt using:
    ```python
    hashed = bcrypt.hashpw(password.encode(), salt)
    ```
  - The `keyfile` stores: `salt || hashed`

### Password Verification
- On login, the app:
  - Reads the stored salt and hash from `keyfile`
  - Re-hashes the entered password using `bcrypt.checkpw()`
  - Grants access only if the result matches the stored hash

---

## Salt Usage

### Purpose of the Salt
- Ensures that two users with the same password will have different password hashes
- Prevents **rainbow table** and **precomputed hash** attacks
- Publicly stored (does **not** need to be secret)

### Storage
- The salt is stored as the first part of the `keyfile`, separated by `b'||'` from the hashed password.

---

## Key Derivation for Encryption

### PBKDF2HMAC
- Used to derive an AES key from the master password
- Prevents reuse of weak or predictable password input as raw encryption key
- Adds computational hardness (delays brute-force attempts)

### Implementation
```python
PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100_000,
    backend=default_backend()
)
```

- **Input**: Master password + salt
- **Output**: 32-byte AES key (Base64-encoded for ```Fernet```)
- **Salt**: reused from ```keyfile``` to maintain consistency between hashing and encryption

---

## AES Encryption (Fernet)

### Why Fernet?
Fernet provides confidentiality through AES encryption and integrity via HMAC

### Fernet Internals
- Encryption algorithm: AES in CBC mode
- Authentication: HMAC-SHA256
- Key size: 128-bit AES key derived from 256-bit input
- Output: A Base64-encoded token containing:
    - Version
    - Timestamp
    - IV (Initialization Vector)
    - Ciphertext
    - HMAC signature

### Usage
```python
fernet = Fernet(derived_key)
token = fernet.encrypt(plaintext.encode())
plaintext = fernet.decrypt(token).decode()
```

## Data Storage
- Passwords are stored in vault.db using SQLite
- Encrypted before insertion using Fernet
- Decrypted at runtime only after authentication and key derivation

## Security Summary
| Component          | Algorithm             | Purpose                             |
|-------------------|------------------------|-------------------------------------|
| Password hashing   | bcrypt                 | Secure master password storage      |
| Salt               | Random 16–22 byte      | Prevents hash reuse / precomputation |
| Key derivation     | PBKDF2-HMAC-SHA256     | Hardens password for encryption     |
| Encryption         | AES (CBC via Fernet)   | Confidentiality of vault data       |
| Authentication     | HMAC-SHA256            | Tamper-proof ciphertext             |
| Database           | SQLite                 | Encrypted local storage             |