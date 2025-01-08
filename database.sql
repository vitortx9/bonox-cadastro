CREATE DATABASE IF NOT EXISTS bonoxcadastro;

USE bonoxcadastro;

CREATE TABLE IF NOT EXISTS usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    firstname VARCHAR(50) NOT NULL,
    lastname VARCHAR(50) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    gender ENUM('masculino', 'feminino', 'outro') NOT NULL,
    password VARCHAR(255) NOT NULL,  -- Renomeado para 'passwor' para corresponder ao campo do formulário
    data_cadastro TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Índices para otimização de consultas
CREATE INDEX idx_email ON usuarios (email);