<?php
require "vendor/autoload.php";//Όταν χρησιμοποιούμε composer όλες οι εξωτερικές βιβλιοθήκες φορτώνονται μέσω του autoload.
require_once('functions.php');//Στο αρχείο αυτό έχουν αποθηκευτεί βοηθητικές συναρτήσεις για τον έλεγχο της υπογραφής των πακέτων/αιτημάτων και την
//διαχείριση του SAML response

session_start();//Ξεκινάμε τα sessions στην php
if (isset($_GET["out"])) {// αν εχει γινει αποσυνδεση session destroy για διαγραφει του cookie phpssid
    session_unset();
    session_destroy();
    header("Location: index.php");//Ανακατευθύνουμε τον χρήστη στην κεντρική σελίδα όπου υπάρχει η φόρμα σύνδεσης
    
}

if (isset($_POST['username']) && isset($_POST['password'])) {//έλεγχος εάν έχει κληθεί η επαλήθευση/επεξεργασία της φόρμας σύνδεσης
    $_SESSION['ERRORS'] = [];// Αρχικοποίηση μεταβλητής σφαλμάτων
    if (empty($_POST['username'])&&empty($_POST['password'])){// έλεγχος αν ειναι αδεια τα πεδια
        $_SESSION['ERRORS'][] = "Παρακαλώ δώστε όνομα και κωδικό χρήστη";
        header("Location: index.php");// Ανακατεύθυνση χρήστη στην σελίδα σύνδεσης με εμφάνιση λάθους για κενά πεδία
        die();//Διακοπή της ροής/εκτέλεσης του κώδικα
    }

    $ldap = ldap_connect("ldap://127.0.0.1");//Σύνδεση με τον τοπικό LDAP server
    $username = htmlentities(trim($_POST['username']));//έλεγχος για επισφαλή κώδικα σε sql injections
    $password = htmlentities(trim($_POST['password']));
    ldap_set_option($ldap, LDAP_OPT_PROTOCOL_VERSION, 3);//δηλώνω LDAPv3
    ldap_set_option($ldap, LDAP_OPT_REFERRALS, 0);// τρόπος με τον οποίο ο server θα διαχειριστεί τα refferals που επιστρέφουν . Τα referrals είναι ενδείξεις πως ο server δεν μπορει να διαχειριστεί το request.
    $auth_user = "cn=" . $username . ",dc=server,dc=local";
    $bind = @ldap_bind($ldap, $auth_user, $password);
    if ($bind) {
      $_SESSION['user'] = $username;//Ο χρήστης έχει συνδεθεί επιτυχώς αποθηκεύω το session του ώστε να μην του ζητήσω πάλι να συνδεθεί.
      if(isset($_POST['SAMLRequest'])){// Έλεγχος εάν ο χρήστης έχει ζητήσει σύνδεση απο περιφερειακό οργανισμό
        handleSAMLRequest($_POST['SAMLRequest']);// Εάν έχει ζητήσει σύνδεση απο περιφερειακό οργανισμό, μέσω της handleSAMLRequest ετοιμάζω το πακέτο που θα επιστρέψω στο
        // SAML Response εσωκλείοντας πληροφορίες του χρήστη όπως το όνομά του. 
      }
    }else{
      $_SESSION['ERRORS'][] = "Λάθoς όvoμα ή κωδικός χρήστη";
    }
}
?>
<html>
<head>
  <title>Κεντρικός οργανισμός</title>
  <link rel="stylesheet" href="css/style.css" /><!-- Αποθήκευση όλων των CSS rules σε εξωτερικό αρχείο για καλύτερη/καθολική χρήση σε όλες τις σελίδες που απαρτίζουν την εφαρμογή -->
</head>
<body>
<div class="topnav">
  <a class="active" href="/">Κεντρικός Οργανισμός</a>
  <!--<a href="/protected.php">Στοιχεία χρήστη</a>-->
</div>
<?php if (isset($_SESSION['ERRORS'])){// Σε περίπτωση που υπάρχουν σφάλματα εμφανίζονται παρακάτω?>
  <ul>
     <?php foreach ($_SESSION['ERRORS'] as $error): // Επειδή αποθηκεύουμε τα σφάλματα σε πίνακα πρέπει να προσπελάσουμε τον πίνακα και να τα παρουσιάσουμε όλα ?>
        <li><?php echo $error ?></li>
    <?php endforeach; ?>
  </ul>
  <?php unset($_SESSION['ERRORS']);}// Αφαιρούμε τα σφάλαματα εφόσον τα δείξουμε ώστε να μην επαναλαμβάνονται σε κάθε φόρτωμα του κώδικα ?>
<?php 
if(isset($_SESSION["user"]) && !isset($_GET['SAMLRequest'])) {// Εάν ο χρήστης έχει συνδεθεί επιτυχώς αλλά δεν έχει έρθει απο περιφερειακό οργανισμό, του εμφανίζουμε απλά τη σελίδα 
  //του κεντρικού οργανισμού
?>
<?php if (isset( $_SESSION['user'] )){?>
<div class="sidenav">
  <h3>Οργανισμοί</h3>
  <a href="org1/protected.php">Οργανισμός 1</a>
  <a href="org2/protected.php">Οργανισμός 2</a>
  <a href="/?out=1">Aπoσύvδεση</a>
</div>
<?php } ?>
<?php
} elseif (isset($_SESSION["user"]) && isset($_GET['SAMLRequest'])) {
  handleSAMLRequest($_GET['SAMLRequest']);// Εάν έχει συνδεθεί επιτυχώς ήδη στον κεντρικό οργανισμό αλλά έρχεται αίτημα για σύνδεση απο περιφερειακό οργνασιμό δεν ξαναζητάμε απο τον 
  // χρήστη να συνδεθεί, παρα ετοιμάζουμε το πακέτο απάντησης με τα δεδομένα που χρειάζονται απο τον περιφερειακό οργανισμό
}else{// Εάν ο χρήστης δεν έχει συνδεθεί εμφανίζουμε την φόρμα σύνδεσης
?>
<h1>Κεντρικός οργαvισμός</h1>
<div class="container">
  <form action="<?=$_SERVER['PHP_SELF']?>" method="POST" autocomplete='off' class='login-form'>
      <label for="username">Όvoμα:</label>
      <input id="username" type="text" name="username" />
      <label for="password">Κωδικός:</label>
      <input id="password" autocomplete="off" type="password" name="password" />
      <?php if(isset($_GET['SAMLRequest'])) { // Σε περίπτωση που σταλεί άιτημα σύνδεση απο περιφερειακό οργανισμό, το πακέτο μαζί με την υπογραφή του οργανισμού, μεταφέρονται σε μια 
        // 'κρυφή' μεταβλητή μέσα στη φόρμα σύνδεσης έτσι ώστε το πρόγραμμά μας να την διεκπαιρεώσει κατά τη διάρκεια της επαλήθευσης του χρήστη. ?>
        <?php if (checkSignature($_GET['SAMLRequest'])){ // Εδώ γίνεται έλεγχος της υπογραφής χρησιμοποιώντας τα κλειδιά ασύμμετρης κρυπτογράφισης. ?>
          <input type="hidden" id="SAMLRequest" name="SAMLRequest" value="<?=$_GET['SAMLRequest']?>">
        <?php } ?>
      <?php } ?>
      <input type="submit" value="Είσοδος" class="submit_button">
  </form>
</div>
<?php } ?>
</body>
</html>
<!-- ?SAMLRequest=longuglystring -->

