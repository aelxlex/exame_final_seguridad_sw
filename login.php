<?php
$servername = "localhost";
$username = "root";
$password = "";
$dbname = "secure_login";

$conn = new mysqli($servername, $username, $password, $dbname);

if ($conn->connect_error) {
  die("Conexión fallida: " . $conn->connect_error);
}

//token de seguridad
session_start();
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$direccion_ip = $_SERVER['REMOTE_ADDR']; // Obtener la dirección IP

if ($_SERVER["REQUEST_METHOD"] == "POST") {
  // Verificar el token CSRF
  if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
    die("Token CSRF inválido.");
  }

  $email = $_POST['email'];
  $pass = $_POST['password'];

  // Validar el formato del correo electrónico
  if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    die("El correo electrónico no es válido.");
  }

  // Verificar los intentos fallidos
  $stmt = $conn->prepare("SELECT intentos, UNIX_TIMESTAMP(ultimo_intento) AS ultimo_intento FROM intentos_login WHERE direccion_ip = ?");
  $stmt->bind_param("s", $direccion_ip);
  $stmt->execute();
  $result = $stmt->get_result();

  $intentos = 0;
  $ultimo_intento = 0;
  $tiempo_actual = time();

  if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    $intentos = $row['intentos'];
    $ultimo_intento = $row['ultimo_intento'];
  }

  // Si hay 3 o más intentos fallidos y no han pasado 5 minutos
  if ($intentos >= 3 && ($tiempo_actual - $ultimo_intento) < 300) {
    die("Por favor, espere 5 minutos antes de intentar nuevamente.");
  } else if ($intentos >= 3 && ($tiempo_actual - $ultimo_intento) >= 300) {
    // Reiniciar el contador después de 5 minutos
    $intentos = 0;
    $stmt = $conn->prepare("UPDATE intentos_login SET intentos = 0 WHERE direccion_ip = ?");
    $stmt->bind_param("s", $direccion_ip);
    $stmt->execute();
  }

  // Verificar si el usuario existe con consulta preparada
  $stmt = $conn->prepare("SELECT id, password FROM users WHERE email = ?");
  $stmt->bind_param("s", $email);
  $stmt->execute();
  $result = $stmt->get_result();

  if ($result->num_rows > 0) {
    $row = $result->fetch_assoc();
    // Verificar la contraseña
    if (password_verify($pass, $row['password'])) {
      die("Inicio de sesión exitoso");
      $_SESSION['id'] = $row['id'];
      exit();

      // Reiniciar el contador si la sesion es correcta
      $stmt = $conn->prepare("UPDATE intentos_login SET intentos = 0 WHERE direccion_ip = ?");
      $stmt->bind_param("s", $direccion_ip);
      $stmt->execute();
    } else {
      echo "Contraseña incorrecta.";

      // actualiza el contador de intentos
      $stmt = $conn->prepare("INSERT INTO intentos_login (direccion_ip, intentos, ultimo_intento) VALUES (?, 1, NOW()) 
                              ON DUPLICATE KEY UPDATE 
                              intentos = intentos + 1, 
                              ultimo_intento = NOW()");
      $stmt->bind_param("s", $direccion_ip);
      $stmt->execute();
    }
  } else {
    echo "El usuario no existe.";

    // Registrar el intento
    $stmt = $conn->prepare("INSERT INTO intentos_login (direccion_ip, intentos, ultimo_intento) VALUES (?, 1, NOW()) 
                            ON DUPLICATE KEY UPDATE 
                            intentos = intentos + 1, 
                            ultimo_intento = NOW()");
    $stmt->bind_param("s", $direccion_ip);
    $stmt->execute();
  }
}
?>

<center>
<form method="POST" action="login.php">
  <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
  <input type="email" name="email" placeholder="E-Mail" required><br>
  <input type="password" name="password" placeholder="Contraseña" required><br>
  <input type="submit" value="Iniciar sesión"><br>
</form>
</center>