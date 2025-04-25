# LocalVault - Python Password Manager
**LocalVault** is a simple yet secure password manager built with Python. It allows you to store and manage your credentials locally, protected by encryption and a master password.

---

## Features
- Master password authentication (bcrypt-hashed)
- AES-256 encryption (via `Fernet`)
- Salted key derivation using PBKDF2
- Encrypted local SQLite vault (`vault.db`)
- Add, retrieve, and delete credentials
- Strong random password generator

---

## Getting Started

### 1. Clone the Repository
```
git clone https://github.com/nick-graves/pwd-manager
cd pwd-manager
```

### 2. Install Dependencies
Make sure you have Python 3.8+ installed, then run:
```
pip install -r requirements.txt
```

### 3. Run the App
```
python main.py
```

## Workflow
![Workflow](images/FlowChart.JPG)


## Project Strcture

```
password_manager/
├── main.py             # CLI app
├── vault_manager.py    # Handles DB and master password logic
├── crypto_utils.py     # Key derivation, encryption/decryption
├── password_utils.py   # Random password generator
├── mfa_utils.py        # (Optional) TOTP setup and QR generation
├── vault.db            # SQLite encrypted vault
├── keyfile             # Stores hashed master password + salt
└── requirements.txt
```


## Security Details
- **Master password** is hashed using bcrypt and stored securely.
- A **random salt** is generated and used with PBKDF2 to derive an AES encryption key.
- Passwords are encrypted using cryptography.fernet (AES in CBC mode + HMAC).
- Salt is stored with the hash (embedded or in ```keyfile```) — safe and standard practice.
> The vault and keyfile are local only — no network or cloud storage involved.

