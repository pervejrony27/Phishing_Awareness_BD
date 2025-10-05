<?php
session_start();
$conn = new mysqli('localhost', 'root', '', 'phishing_bd');

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $conn->real_escape_string($_POST['username']);
    $password = $_POST['password'];

    // Search by username or email
    $result = $conn->query("SELECT * FROM users WHERE username='$username' OR email='$username' LIMIT 1");

    if ($result->num_rows === 1) {
        $user = $result->fetch_assoc();
        if (password_verify($password, $user['password'])) {
            $_SESSION['user_id'] = $user['id'];
            $_SESSION['username'] = $user['username'];
            header("Location: ../index.html"); // Redirect after login
            exit();
        } else {
            header("Location: ../login.html?login_error=" . urlencode("Incorrect password"));
            exit();
        }
    } else {
        header("Location: ../login.html?login_error=" . urlencode("User not found"));
        exit();
    }
}
?>
