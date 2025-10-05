<?php
session_start();

// Destroy all session data
session_unset();
session_destroy();

// Redirect back to login page with a message
header("Location: ../login.html?logged_out=1");
exit();
?>
