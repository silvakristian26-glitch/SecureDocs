import os
import hmac
import hashlib
import secrets
from functools import wraps

import pymysql
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, abort, g)
from werkzeug.security import check_password_hash

load_dotenv()

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["SECRET_KEY"],
    SESSION_COOKIE_HTTPONLY=True,      # JS não lê o cookie
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=1800,   # sessão expira em 30 min
)
fernet = Fernet(os.environ["FERNET_KEY"].encode())
PEPPER = os.environ["HASH_PEPPER"].encode()


# ---------------- Banco ----------------
def db():
    if "db" not in g:
        g.db = pymysql.connect(
            host=os.environ["DB_HOST"], user=os.environ["DB_USER"],
            password=os.environ["DB_PASSWORD"], database=os.environ["DB_NAME"],
            charset="utf8mb4", cursorclass=pymysql.cursors.DictCursor,
            autocommit=True,
        )
    return g.db


@app.teardown_appcontext
def fechar_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


# ---------------- Proteção de dados ----------------
def cifrar(texto):
    return fernet.encrypt(texto.encode()).decode() if texto else None


def decifrar(texto):
    return fernet.decrypt(texto.encode()).decode() if texto else ""


def hash_busca(texto):
    return hmac.new(PEPPER, texto.encode(), hashlib.sha256).hexdigest()


def so_digitos(texto):
    return "".join(c for c in (texto or "") if c.isdigit())


def cpf_valido(cpf):
    if len(cpf) != 11 or cpf == cpf[0] * 11:
        return False
    for n in (9, 10):
        soma = sum(int(cpf[i]) * (n + 1 - i) for i in range(n))
        dig = (soma * 10 % 11) % 10
        if dig != int(cpf[n]):
            return False
    return True


def mascarar_cpf(cpf):
    return f"***.{cpf[3:6]}.***-{cpf[9:]}" if cpf else "—"


def registrar_log(acao, entidade=None, entidade_id=None, usuario_id=None):
    with db().cursor() as cur:
        cur.execute(
            "INSERT INTO logs_auditoria (usuario_id, acao, entidade, entidade_id, ip) "
            "VALUES (%s, %s, %s, %s, %s)",
            (usuario_id or session.get("uid"), acao, entidade, entidade_id,
             request.remote_addr),
        )


# ---------------- Segurança da aplicação ----------------
@app.before_request
def validar_csrf():
    if request.method == "POST":
        token = request.form.get("csrf_token", "")
        if not hmac.compare_digest(token, session.get("csrf_token", "")):
            abort(400, "Token CSRF inválido")


@app.context_processor
def injetar_contexto():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return {"csrf_token": session["csrf_token"],
            "usuario_nome": session.get("nome"),
            "perfil": session.get("perfil")}


@app.after_request
def cabecalhos_seguranca(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"   # não guardar dados pessoais em cache
    return resp


def login_obrigatorio(perfil=None):
    def decorador(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if "uid" not in session:
                return redirect(url_for("login"))
            if perfil and session.get("perfil") != perfil:
                registrar_log("ACESSO_NEGADO", request.endpoint)
                abort(403)
            return f(*args, **kwargs)
        return wrapper
    return decorador


# ---------------- Rotas ----------------
@app.route("/")
def inicio():
    return redirect(url_for("dashboard"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        senha = request.form.get("senha", "")
        with db().cursor() as cur:
            cur.execute("SELECT * FROM usuarios WHERE email = %s AND ativo = TRUE", (email,))
            user = cur.fetchone()
        if user and check_password_hash(user["senha_hash"], senha):
            session.clear()                       # evita fixação de sessão
            session.permanent = True
            session.update(uid=user["id"], nome=user["nome"], perfil=user["perfil"])
            registrar_log("LOGIN_OK", "usuarios", user["id"])
            return redirect(url_for("dashboard"))
        registrar_log("LOGIN_FALHA", "usuarios", user["id"] if user else None,
                      usuario_id=user["id"] if user else None)
        flash("E-mail ou senha incorretos.")      # mensagem genérica de propósito
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_obrigatorio()
def logout():
    registrar_log("LOGOUT")
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_obrigatorio()
def dashboard():
    with db().cursor() as cur:
        cur.execute("SELECT COUNT(*) AS n FROM clientes WHERE anonimizado_em IS NULL")
        ativos = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n FROM clientes WHERE anonimizado_em IS NOT NULL")
        anonimizados = cur.fetchone()["n"]
        cur.execute("SELECT COUNT(*) AS n FROM logs_auditoria WHERE DATE(data_hora) = CURDATE()")
        eventos_hoje = cur.fetchone()["n"]
    return render_template("dashboard.html", ativos=ativos,
                           anonimizados=anonimizados, eventos_hoje=eventos_hoje)


@app.route("/clientes")
@login_obrigatorio()
def clientes():
    busca = so_digitos(request.args.get("cpf"))
    sql = "SELECT id, nome, cpf_cifrado, finalidade, criado_em, anonimizado_em FROM clientes"
    params = ()
    if busca:
        sql += " WHERE cpf_hash = %s"            # busca pelo hash, sem decifrar a base
        params = (hash_busca(busca),)
    sql += " ORDER BY criado_em DESC"
    with db().cursor() as cur:
        cur.execute(sql, params)
        linhas = cur.fetchall()
    for c in linhas:
        c["cpf_mascarado"] = mascarar_cpf(decifrar(c["cpf_cifrado"]))
    return render_template("clientes.html", clientes=linhas, busca=busca)


@app.route("/clientes/novo", methods=["GET", "POST"])
@login_obrigatorio()
def cliente_novo():
    if request.method == "POST":
        f = request.form
        nome = f.get("nome", "").strip()
        cpf = so_digitos(f.get("cpf"))
        email = f.get("email", "").strip().lower()
        telefone = so_digitos(f.get("telefone"))
        finalidade = f.get("finalidade", "").strip()

        erros = []
        if len(nome) < 3:
            erros.append("Informe o nome completo.")
        if not cpf_valido(cpf):
            erros.append("CPF inválido.")
        if not finalidade:
            erros.append("Informe a finalidade do tratamento.")
        if f.get("consentimento") != "sim":
            erros.append("Sem consentimento do titular o cadastro não pode ser feito.")
        if erros:
            for e in erros:
                flash(e)
            return render_template("cliente_form.html", form=f), 400

        try:
            with db().cursor() as cur:
                cur.execute(
                    "INSERT INTO clientes (nome, cpf_cifrado, cpf_hash, email_cifrado, "
                    "telefone_cifrado, finalidade, consentimento, data_consentimento, criado_por) "
                    "VALUES (%s, %s, %s, %s, %s, %s, TRUE, NOW(), %s)",
                    (nome, cifrar(cpf), hash_busca(cpf), cifrar(email),
                     cifrar(telefone), finalidade, session["uid"]),
                )
                novo_id = cur.lastrowid
        except pymysql.err.IntegrityError:
            flash("Já existe um cliente com esse CPF.")
            return render_template("cliente_form.html", form=f), 409

        registrar_log("CLIENTE_CRIADO", "clientes", novo_id)
        flash("Cliente cadastrado.")
        return redirect(url_for("clientes"))
    return render_template("cliente_form.html", form={})


@app.route("/clientes/<int:cid>")
@login_obrigatorio(perfil="admin")
def cliente_ver(cid):
    with db().cursor() as cur:
        cur.execute("SELECT * FROM clientes WHERE id = %s", (cid,))
        c = cur.fetchone()
    if not c:
        abort(404)
    registrar_log("DADOS_VISUALIZADOS", "clientes", cid)   # acesso a dado pessoal fica registrado
    dados = {"cpf": decifrar(c["cpf_cifrado"]), "email": decifrar(c["email_cifrado"]),
             "telefone": decifrar(c["telefone_cifrado"])}
    return render_template("cliente_ver.html", c=c, dados=dados)


@app.route("/clientes/<int:cid>/anonimizar", methods=["POST"])
@login_obrigatorio(perfil="admin")
def cliente_anonimizar(cid):
    with db().cursor() as cur:
        cur.execute(
            "UPDATE clientes SET nome = 'Titular anonimizado', cpf_cifrado = NULL, cpf_hash = NULL, "
            "email_cifrado = NULL, telefone_cifrado = NULL, anonimizado_em = NOW() "
            "WHERE id = %s AND anonimizado_em IS NULL", (cid,))
    registrar_log("CLIENTE_ANONIMIZADO", "clientes", cid)
    flash("Dados do titular anonimizados.")
    return redirect(url_for("clientes"))


@app.route("/auditoria")
@login_obrigatorio(perfil="admin")
def auditoria():
    with db().cursor() as cur:
        cur.execute(
            "SELECT l.data_hora, l.acao, l.entidade, l.entidade_id, l.ip, u.nome "
            "FROM logs_auditoria l LEFT JOIN usuarios u ON u.id = l.usuario_id "
            "ORDER BY l.id DESC LIMIT 200")
        logs = cur.fetchall()
    return render_template("auditoria.html", logs=logs)


@app.errorhandler(403)
def proibido(_):
    return render_template("erro.html", msg="Seu perfil não tem acesso a esta página."), 403


if __name__ == "__main__":
    app.run(debug=False)
