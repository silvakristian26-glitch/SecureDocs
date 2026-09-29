"""Gera as chaves secretas para colar no .env"""
import secrets
from cryptography.fernet import Fernet

print(f"SECRET_KEY={secrets.token_hex(32)}")
print(f"FERNET_KEY={Fernet.generate_key().decode()}")
print(f"HASH_PEPPER={secrets.token_hex(32)}")
