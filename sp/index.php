<?php
require "vendor/autoload.php";
$deserializationContext = new \LightSaml\Model\Context\DeserializationContext();
session_start();
if (isset($_POST['SAMLResponse'])){// Εδώ λαμβάνουμε το HTTP Post response που λαμβάνουμε απο τον κεντρικό οργανισμό
  $response= base64_decode($_POST['SAMLResponse']);// Το περιεχόμενο είναι κωδικοποιημένο με base64 οπότε χρειάζεται η μετατροπή του σε xml
  $deserializationContext->getDocument()->loadXML($response);
  $response = new \LightSaml\Model\Protocol\Response();// Μετατρέπουμε το xml σε αντικείμενο
  $response->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);
  $signatureReader= $response->getSignature();
  $key = \LightSaml\Credential\KeyHelper::createPublicKey(
      \LightSaml\Credential\X509Certificate::fromFile('ssl/cert.crt')
  );
  try {
      $ok = $signatureReader->validate($key); // Ελέγχουμε ξανά την υπογραφή της απάντησης ώστε να είμαστε σίγουροι ότι μας έχει απαντήσει ο IDP.

      if ($ok) {
          print "Signature OK\n";
      } else {
          print "Signature not validated";
      }
    } catch (\Exception $ex) {
        print "Signature validation failed\n";
    }
  // Εδώ διαβάζουμε τα κλειδιά και το πιστοποιητικό
  $credential = new \LightSaml\Credential\X509Credential(
    \LightSaml\Credential\X509Certificate::fromFile('ssl/cert.crt'),
    \LightSaml\Credential\KeyHelper::createPrivateKey('ssl/pkey.key', '', true)
  );
  
  // και ξεκινάμε την αποκρυπτογράφηση των δεδομένων που μας έστειλε ο LDAP
  /** @var \LightSaml\Model\Assertion\EncryptedAssertionReader $reader */
  $reader = $response->getFirstEncryptedAssertion();
  $decryptDeserializeContext = new \LightSaml\Model\Context\DeserializationContext();
  $assertion = $reader->decryptMultiAssertion([$credential], $decryptDeserializeContext);
  // Εφόσον τα αποκρυπτογραφήσουμε τα διαβάζουμε ένα ένα μέχρι να βρούμε αυτά που μας ενδιαφέρουν. Εδώ συγκεκριμένα το όνομα του χρήστη
  foreach ($assertion->getFirstAttributeStatement()->getAllAttributes() as $attribute) {
    if ($attribute->getName()==="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"){
      $_SESSION['user'] = $attribute->getFirstAttributeValue();
    }
  }
  
}

if (isset($_GET["out"])) {
    session_unset();
    session_destroy();
    header("Location: index.php");
}
?>
<html>
  <head>
    <title>Περιφερειακός Oργανισμός</title>
    <meta charset="UTF-8" />
    <link rel="stylesheet" href="css/style.css" />
  </head>
  <body>
  <div class="topnav">
  <a class="active" href="/">Περιφερειακός Oργανισμός</a>
</div>
<?php if (isset($_SESSION['ERRORS'])){?>
  <ul>
     <?php foreach ($_SESSION['ERRORS'] as $error): ?>
        <li><?php echo $error ?></li>
    <?php endforeach; ?>
  </ul>
  <?php unset($_SESSION['ERRORS']);} ?>
<?php 
  if(isset($_SESSION["user"])) { // user correctly connected
?>
<div class="sidenav">
  <h3>Οργανισμοί</h3>
  <a href="org1/protected.php">Οργανισμός 1</a>
  <a href="org2/protected.php">Οργανισμός 2</a>
  <a href="/?out=1">Αποσύνδεση</a>
</div>
<?php
} else {
?>
<h1>Περιφερειακός οργαvισμός</h1>

<div class="container">
  <?php
    $authnRequest = new \LightSaml\Model\Protocol\AuthnRequest(); // setarisma για το saml request μεσω της βιβλιοθήκης lightsaml
    $authnRequest
        ->setAssertionConsumerServiceURL('http://192.168.1.25/index.php') // ορίζουμε το url του SP ωστε να ανακατευθύνει τον χρήστη, μετά τη σύνδεση
        ->setProtocolBinding(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST)// Ορίζουμε ότι η ανακατεύθυνση θα γίνει με HTTP POST
        ->setID(\LightSaml\Helper::generateID())// Δημιουργούμε ένα ID για τον έλεγχο των request απο και προς τον LDAP.
        ->setIssueInstant(new \DateTime())
        ->setDestination('http://192.168.1.14/index.php') // είναι το url του LDAP
        ->setIssuer(new \LightSaml\Model\Assertion\Issuer('http://192.168.1.14'));// ως issuer δηλώνεται ο ldap μας
        //var_dump($authnRequest);
        $certificate = \LightSaml\Credential\X509Certificate::fromFile('ssl/cert.crt');
        $privateKey = \LightSaml\Credential\KeyHelper::createPrivateKey('ssl/pkey.key', '', true);
        $authnRequest->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter($certificate, $privateKey));// Υπογράφουμε το request
        $serializationContext = new \LightSaml\Model\Context\SerializationContext();// για να μπορουμε να δουλέψουμε με xml
    
        $authnRequest->serialize($serializationContext->getDocument(), $serializationContext);// parse of the document
        
        //var_dump($serializationContext->getDocument()->saveXML());
    ?>
  <a class="btn" href="http://192.168.1.14/index.php?SAMLRequest=<?=base64_encode($serializationContext->getDocument()->saveXML()) // Εδώ μετατρέπουμε το request απο XML σε συμβολοσειρά
  // ώστε να μπορέσει να σταλεί με GET url στη φόρμα σύνδεσης του LDAP?>">Login via SAML</a>
</div>
<?php } ?>
    </body>
</html>
<!-- ?SAMLRequest=longuglystring -->

