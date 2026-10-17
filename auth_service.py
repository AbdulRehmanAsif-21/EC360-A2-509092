import hashlib
import os


def hash_password(password: str) -> str:
    """Return a salted PBKDF2 hash of the supplied password."""
    if not password:
        raise ValueError("Password cannot be empty.")

    salt = os.urandom(16)

    password_hash = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        200_000
    )

    return f"{salt.hex()}:{password_hash.hex()}"


def register_user(email: str, password: str) -> dict:
    """Validate registration input and return a user record."""
    email = email.strip().lower()

    if not email or "@" not in email:
        raise ValueError("A valid email address is required.")

    if not password:
        raise ValueError("Password cannot be empty.")

    return {
        "email": email,
        "password_hash": hash_password(password)
    }
