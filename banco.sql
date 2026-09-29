-- =========================================================
-- SecureDocs - Banco de dados com dados pessoais (LGPD)
-- Execute no MySQL como root:  mysql -u root -p < banco.sql
-- =========================================================
CREATE DATABASE IF NOT EXISTS securedocs
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE securedocs;

-- Usuários do sistema (quem opera os dados)
CREATE TABLE IF NOT EXISTS usuarios (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  nome        VARCHAR(100) NOT NULL,
  email       VARCHAR(150) NOT NULL UNIQUE,
  senha_hash  VARCHAR(255) NOT NULL,                 -- nunca senha em texto puro
  perfil      ENUM('admin','operador') NOT NULL DEFAULT 'operador',
  ativo       BOOLEAN NOT NULL DEFAULT TRUE,
  criado_em   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- Titulares dos dados (clientes)
CREATE TABLE IF NOT EXISTS clientes (
  id                  INT AUTO_INCREMENT PRIMARY KEY,
  nome                VARCHAR(150) NOT NULL,
  cpf_cifrado         TEXT NULL,          -- criptografado (Fernet/AES) pela aplicação
  cpf_hash            CHAR(64) NULL UNIQUE, -- HMAC-SHA256: permite buscar sem decifrar
  email_cifrado       TEXT NULL,
  telefone_cifrado    TEXT NULL,
  finalidade          VARCHAR(255) NOT NULL, -- LGPD art. 6º, I: finalidade do tratamento
  consentimento       BOOLEAN NOT NULL,      -- LGPD art. 7º, I / art. 8º
  data_consentimento  DATETIME NOT NULL,
  criado_por          INT NOT NULL,
  criado_em           DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  anonimizado_em      DATETIME NULL,         -- LGPD art. 18: eliminação/anonimização
  CONSTRAINT fk_cliente_usuario FOREIGN KEY (criado_por) REFERENCES usuarios(id)
);

-- Trilha de auditoria (quem fez o quê, quando)
CREATE TABLE IF NOT EXISTS logs_auditoria (
  id          BIGINT AUTO_INCREMENT PRIMARY KEY,
  usuario_id  INT NULL,
  acao        VARCHAR(50) NOT NULL,
  entidade    VARCHAR(50) NULL,
  entidade_id INT NULL,
  ip          VARCHAR(45) NULL,
  data_hora   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT fk_log_usuario FOREIGN KEY (usuario_id) REFERENCES usuarios(id),
  INDEX idx_log_data (data_hora)
);

-- Usuário da aplicação com privilégio mínimo:
-- sem DELETE/DROP -> a aplicação não consegue apagar a trilha de auditoria.
CREATE USER IF NOT EXISTS 'securedocs_app'@'localhost' IDENTIFIED BY 'TroqueEstaSenha!2026';
GRANT SELECT, INSERT, UPDATE ON securedocs.* TO 'securedocs_app'@'localhost';
FLUSH PRIVILEGES;
