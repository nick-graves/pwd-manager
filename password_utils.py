# password_utils.py

import secrets
import string

def generate_password(length=16, use_special_chars=True) -> str:
    """
    Generate a secure random password.
    
    Args:
        length (int): Length of the password to generate.
        use_special_chars (bool): Whether to include special characters.

    Returns:
        str: A randomly generated password.
    """
    characters = string.ascii_letters + string.digits
    if use_special_chars:
        characters += "!@#$%^&*()-_=+[]{};:,.<>/?"

    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password