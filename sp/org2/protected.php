<?php
// initialize session
session_start();

if(!isset($_SESSION['user'])) {// direct user to the right page
        header("Location: ../index.php");
        die();
}
//conection with the ldap server
$ldap = ldap_connect("ldap://127.0.0.1");
ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);
ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);
$auth_user = "cn=admin,dc=server,dc=local";
$bind = @ldap_bind($ldap, $auth_user, $password);
$filter = "(&(cn=" . $_SESSION['user'] . ")(ou=org2))";
$result = ldap_search($ldap, "dc=server,dc=local", $filter) or exit('Error');
$entries = ldap_get_entries($ldap, $result);
if (!in_array('org2', $entries[0]['ou'])) {
  $_SESSION['ERRORS'][] = "Δεν είστε εγγεγραμμένος σε συτόν τον οργανισμό.";
  header("Location: ../index.php");
  die();
}

?>
<html> 
  <head>
    <title>Περιφερειακός Oργανισμός 2</title>
    <meta charset="UTF-8" />
    <link rel="stylesheet" href="../css/style.css" />
  </head>
<body>
  <div class="topnav">
    <a class="active" href="/">Περιφερειακός Οργαvισμός 2</a>
    <a  href="/?out=1">Αποσύνδεση</a>
  </div>
  <h1 style="text-align: center">Καλώς ήρθες: <?= $_SESSION['user'] ?>!</h1>
</body>
</html>