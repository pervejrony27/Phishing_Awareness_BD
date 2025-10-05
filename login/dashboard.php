<?php
session_start();
if(!isset($_SESSION['username'])){
    header("Location: login/login.html");
    exit;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Dashboard — Phishing Awareness BD</title>
    <link rel="stylesheet" href="css/index.css">
</head>
<body>
    <?php include 'navbar.php'; ?> <!-- Optional: move navbar to a separate file -->

    <section class="dashboard">
        <h1>Welcome, <?php echo htmlspecialchars($_SESSION['username']); ?>!</h1>
        <p>This is your dashboard.</p>
        <ul>
            <li><a href="profile.php">Profile</a></li>
            <li><a href="login/logout.php">Logout</a></li>
        </ul>
    </section>
</body>
</html>
