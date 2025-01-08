<?php
// functions.php

function sanitize_input($data)
{
    return htmlspecialchars(stripslashes(trim($data)));
}

function redirect_with_error($location, $error)
{
    header("Location: $location?error=" . urlencode($error));
    exit();
}

function generate_csrf_token()
{
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
}

function validate_csrf_token($token)
{
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Função para validar o formato do e-mail
function validate_email($email)
{
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Função de validação de senha
function validate_password($password)
{
    // Senha deve ter pelo menos 8 caracteres
    return strlen($password) >= 8;
}
?>