"""Cria o primeiro usuário administrador."""
import getpass
from werkzeug.security import generate_password_hash
from app import app, db

nome = input("Nome: ").strip()
email = input("E-mail: ").strip().lower()
senha = getpass.getpass("Senha (mín. 10 caracteres): ")
if len(senha) < 10:
    raise SystemExit("Senha muito curta.")

with app.app_context():
    with db().cursor() as cur:
        cur.execute(
            "INSERT INTO usuarios (nome, email, senha_hash, perfil) VALUES (%s, %s, %s, 'admin')",
            (nome, email, generate_password_hash(senha)),
        )
print("Administrador criado.")
