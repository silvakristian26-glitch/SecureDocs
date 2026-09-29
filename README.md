# SecureDocs — cadastro de dados pessoais com LGPD

Flask + MySQL + HTML/CSS. Dados sensíveis criptografados, controle de acesso por perfil,
auditoria e anonimização.

## Rodar no VS Code (Windows)

1. Instale Python 3.11+, MySQL 8 e a extensão "Python" no VS Code.
2. Abra a pasta `SecureDocs` no VS Code (File > Open Folder) e abra o terminal (Ctrl+`).
3. Crie o banco:
   mysql -u root -p < banco.sql
4. Ambiente virtual e dependências:
   python -m venv venv
   venv\Scripts\activate          (Linux/Mac: source venv/bin/activate)
   pip install -r requirements.txt
5. Chaves: copie `.env.example` para `.env`, rode `python gerar_chaves.py`
   e cole as 3 linhas geradas no `.env`.
6. Primeiro admin:  python criar_admin.py
7. Rodar:  python app.py   ->  http://127.0.0.1:5000

## O que atende de LGPD

| Requisito | Como foi feito |
|---|---|
| Segurança (art. 46) | CPF, e-mail e telefone cifrados com Fernet (AES-128 + HMAC); senhas com hash (werkzeug/scrypt) |
| Busca sem expor dado | `cpf_hash` = HMAC-SHA256 com pepper, busca sem decifrar a base |
| Necessidade / minimização | Lista mostra CPF mascarado; dado completo só para admin |
| Finalidade (art. 6º) | Campo obrigatório `finalidade` |
| Consentimento (art. 7º/8º) | Checkbox obrigatório + `data_consentimento` |
| Eliminação (art. 18) | Anonimização do titular pelo admin |
| Prestação de contas (art. 6º, X) | `logs_auditoria` de login, visualização, criação e anonimização |
| Privilégio mínimo | Usuário do banco sem DELETE: a aplicação não apaga a auditoria |
| Web | CSRF, cookie HttpOnly, sessão de 30 min, `Cache-Control: no-store`, SQL parametrizado |

## Próximos passos (para citar na entrevista)
- HTTPS em produção e `SESSION_COOKIE_SECURE=True`
- Bloqueio após N tentativas de login e MFA
- Chave de criptografia em cofre (Azure Key Vault / AWS KMS), com rotação
- Backup cifrado e política de retenção
