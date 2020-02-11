<?php
// initialize session
session_start();

if(!isset($_SESSION['user'])) {
        header("Location: ../index.php");
        die();
}
//εδω χρειαζόμαστε να δούμε τα δικαιώματα του χρήστη γι αυτό και ξανακοιτάμε τον LDAP το ίδιο γίνεται και στα υπόλοιπα protected.php
$ldap = ldap_connect("ldap://127.0.0.1");
ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
$auth_user = "cn=admin,dc=server,dc=local";
$bind = @ldap_bind($ldap, $auth_user, $password);
$filter = "(&(cn=" . $_SESSION['user'] . ")(ou=org1))";
$result = ldap_search($ldap, "dc=server,dc=local", $filter) or exit('Error');
$entries = ldap_get_entries($ldap, $result);
if (!in_array('org1', $entries[0]['ou'])) {
  $_SESSION['ERRORS'][] = "Δεν είστε εγγεγραμμένος σε συτόν τον οργανισμό.";
  header("Location: ../index.php");
  die();
}

?>
<html>
<head> 
<meta charset="UTF-8" />
<title>Κεντρικός οργανισμός 1</title>
  <link rel="stylesheet" href="../css/style.css" />
</head>
<body>
<div class="topnav">
  <a class="active" href="/">Κεντρικός Οργαvισμός 1</a>
  <a  href="/?out=1">Αποσύνδεση</a>
</div>
<h1 style="text-align: center">Καλώς ήρθες: <?= $_SESSION['user'] ?>!</h1>
</body>
</html>
