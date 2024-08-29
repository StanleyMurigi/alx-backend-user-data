#!/usr/bin/env python3
"""Encrypting passwords
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hash a password using bcrypt.

    Args:
        password (str): The password to hash.

    Returns:
        bytes: The salted, hashed password.
    """
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates a password against a hashed password using bcrypt.

    Args:
        hashed_password (bytes): The hashed password.
        passwors (str): The password to validate.

    Returns:
        bool: True if the password matches the hashed password, False otherwise
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
