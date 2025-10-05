<?php
session_start();
$conn = new mysqli('localhost', 'root', '', 'phishing_bd');

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $conn->real_escape_string($_POST['username']);
    $email = $conn->real_escape_string($_POST['email']);
    $password = $_POST['password'];
    $confirm_password = $_POST['confirm_password'];

    if ($password !== $confirm_password) {
        header("Location: ../login.html?reg_error=" . urlencode("Passwords do not match"));
        exit();
    }

    // Hash password
    $password_hash = password_hash($password, PASSWORD_DEFAULT);

    // Check if email already exists
    $check = $conn->query("SELECT id FROM users WHERE email='$email'");
    if ($check->num_rows > 0) {
        header("Location: ../login.html?reg_error=" . urlencode("Email already registered"));
        exit();
    }

    // Insert user
    $conn->query("INSERT INTO users (username, email, password) VALUES ('$username','$email','$password_hash')");
    header("Location: ../login.html?reg_success=1");
    exit();
}
?>
