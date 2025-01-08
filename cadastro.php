<?php
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("X-XSS-Protection: 1; mode=block");
header("Strict-Transport-Security: max-age=31536000; includeSubDomains; preload");
header("Referrer-Policy: no-referrer-when-downgrade");
header("Content-Security-Policy: default-src 'self'; script-src 'self' 'nonce-random'; style-src 'self'; img-src 'self' data:;");

// Inicia a sessão
session_start();

// Inclui os arquivos necessários
include 'db_connect.php';
include 'functions.php';

// Verifica se o formulário foi enviado
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Verifica o token CSRF
    if (!isset($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die("Token CSRF inválido.");
    }

    // Captura e sanitiza os dados do formulário
    $firstname = sanitize_input($_POST['firstname']);
    $lastname = sanitize_input($_POST['lastname']);
    $email = sanitize_input($_POST['email']);
    $password = sanitize_input($_POST['password']);
    $gender = sanitize_input($_POST['gender']);

    // Valida o e-mail
    if (!validate_email($email)) {
        header("Location: cadastro.php?error=invalid_email");
        exit();
    }

    // Valida a senha
    if (!validate_password($password)) {
        header("Location: cadastro.php?error=password_invalid");
        exit();
    }

    // Conexão com o banco de dados
    $conn = db_connect();

    // Prepara a consulta SQL para verificar se o e-mail já está registrado
    $sql = "SELECT id FROM usuarios WHERE email = ?";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("s", $email);
    $stmt->execute();
    $stmt->store_result();

    if ($stmt->num_rows > 0) {
        // E-mail já registrado, redireciona com mensagem de erro
        header("Location: cadastro.php?error=email_registered");
        exit();
    }

    $stmt->close();

    // Criptografa a senha
    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    // Prepara a consulta SQL para inserir o novo usuário
    $sql = "INSERT INTO usuarios (firstname, lastname, email, password, gender) VALUES (?, ?, ?, ?, ?)";
    $stmt = $conn->prepare($sql);
    $stmt->bind_param("sssss", $firstname, $lastname, $email, $hashed_password, $gender);

    if ($stmt->execute()) {
        // Cadastro bem-sucedido, redireciona para a página de login
        header("Location: submit.html?success=registered");
        exit();
    } else {
        // Erro ao cadastrar, redireciona com mensagem de erro
        header("Location: cadastro.php?error=registration_failed");
        exit();
    }

    $stmt->close();
    $conn->close();
}

// Gera um token CSRF para o formulário
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Gerar nonce para CSP
$nonce = bin2hex(random_bytes(16));
?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta name="description" content="Nossa empresa foi criada no intuito de ajudar os necessitados.">
    <link rel="icon" href="img/tb.png" type="image/x-icon">
    <link rel="stylesheet" href="style/cadastro.css">
    <meta http-equiv="Content-Security-Policy"
        content="default-src 'self'; script-src 'self' 'nonce-<?php echo $nonce; ?>'; style-src 'self'; img-src 'self' data:;">
    <title>Bonox - Cadastro para Sorteio</title>
</head>
<body>
    <header>
        <img src="img/topbonox.png" alt="logo da Top Bonox">
    </header>
    <div class="container">
        <h1>Cadastro</h1>
        <p>Para participar do sorteio de 1 Gift Card Google Play Store no valor de R$20,00, basta se cadastrar em nosso
            site.<br><br>Preencha os dados abaixo para participar do nosso sorteio.</p>

        <!-- Mensagens de erro -->
        <?php
        if (isset($_GET['error'])) {
            $error_messages = [
                'invalid_email' => 'Formato de e-mail inválido.',
                'password_invalid' => 'A senha deve ter pelo menos 8 caracteres.',
                'email_registered' => 'Este e-mail já está registrado.',
                'registration_failed' => 'Falha ao registrar. Tente novamente.'
            ];
            $error_code = $_GET['error'];
            if (array_key_exists($error_code, $error_messages)) {
                echo '<p class="error">' . $error_messages[$error_code] . '</p>';
            }
        }
        ?>

        <form action="cadastro.php" method="post">
            <div class="form-group">
                <label for="firstname">Nome:</label>
                <input type="text" id="firstname" name="firstname" placeholder="Seu nome" required>
            </div>

            <div class="form-group">
                <label for="lastname">Sobrenome:</label>
                <input type="text" id="lastname" name="lastname" placeholder="Seu sobrenome" required>
            </div>

            <div class="form-group">
                <label for="email">E-mail:</label>
                <input type="email" id="email" name="email" placeholder="seugmail@gmail.com" required>
            </div>

            <div class="form-group">
                <label for="password">Senha:</label>
                <input type="password" id="password" name="password" placeholder="Sua senha" required>
            </div>

            <div class="form-group">
                <label for="gender">Gênero:</label>
                <select id="gender" name="gender" required>
                    <option value="">Selecione seu gênero</option>
                    <option value="masculino">Masculino</option>
                    <option value="feminino">Feminino</option>
                    <option value="outro">Outro</option>
                </select>
            </div>

            <!-- Adiciona o token CSRF ao formulário -->
            <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">

            <button type="submit">Participar do Sorteio</button>
        </form>
    </div>

    <footer>
        <p>&copy; Top Bonox 2024. Todos os direitos reservados.</p>
    </footer>

</body>
</html>