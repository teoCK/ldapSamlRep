<?php
//Για τη δημιουργία και τον έλεγχο request και response(μαζί με τον έλεγχο τον ψηφιακων υπογραφών) έγιναν με ακολουθώντας το
//https://www.lightsaml.com/LightSAML-Core/Cookbook/
function handleSAMLRequest($request)
{
    if (!checkSignature($request)){// Εδώ γίνεται πάλι έλεγχος της υπογραφής του πακέτου για την αυθεντικότητα του αιτήματος.
        throw new Exception("Signature not valid.");
    }
    
    $decoded = str_replace(" ","+",$request); // Επειδή ο φυλλομετρητής αντικαθιστά το σύμβολο + με το κενό, επαναφέρουμε το σύμβολο στη θέση του γιατί αλλιώς η μετατροπή του
    //base64 σε κείμενο δεν θα είναι εφικτή.
    $xml = base64_decode($decoded); // Το αίτημα και γενικότερα η επικοινωνία μέσω SAML βασίζεται σε xml μορφή δεδομένων, επομένως δεν είναι εφικτή η μεταφορά τους μέσω πακέτων HTTP
    // Το base64 είναι μια κωδικοποίηση η οποία παράγει μια συμβολοσειρά απο την οποία μπορεί να ανακληθεί το περιεχόμενό της.
    //var_dump($decoded);exit;
    
    $deserializationContext = new \LightSaml\Model\Context\DeserializationContext();
    $deserializationContext->getDocument()->loadXML($xml); // Εφόσον έχουμε το XML το οποίο περιγράφει τη διαδικασία της σύνδεσης όπως, το url στο οποίο πρέπει να ανακατευθυνθεί 
    // ο χρήστης μετά την είσοδό του κλπ. 
  
    $authnRequest = new \LightSaml\Model\Protocol\AuthnRequest();
    //echo "AuthRequest passed";
    $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext); 
    // Μετατρέπουμε το xml σε php αντικείμενα.

    $assertion = new \LightSaml\Model\Assertion\Assertion(); // Ξεκινάμε να δημιουργούμε την απάντηση που θα στείλουμε πίσω στον περιφερειακό οργανισμό.
    $assertion
      ->setId(\LightSaml\Helper::generateID())
      ->setIssueInstant(new \DateTime())
      ->setIssuer(new \LightSaml\Model\Assertion\Issuer('http://idp.teo.com'))
      ->setSubject(
          (new \LightSaml\Model\Assertion\Subject())
              ->setNameID(new \LightSaml\Model\Assertion\NameID('email.teo.com', \LightSaml\SamlConstants::NAME_ID_FORMAT_EMAIL))
              ->addSubjectConfirmation(
                  (new \LightSaml\Model\Assertion\SubjectConfirmation())
                      ->setMethod(\LightSaml\SamlConstants::CONFIRMATION_METHOD_BEARER)
                      ->setSubjectConfirmationData(
                          (new \LightSaml\Model\Assertion\SubjectConfirmationData())
                              ->setInResponseTo($authnRequest->getId())
                              ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
                              ->setRecipient($authnRequest->getAssertionConsumerServiceURL())
                      )
              )
      )
      ->setConditions(
          (new \LightSaml\Model\Assertion\Conditions())
              ->setNotBefore(new \DateTime())
              ->setNotOnOrAfter(new \DateTime('+1 MINUTE'))
              ->addItem(
                  new \LightSaml\Model\Assertion\AudienceRestriction([$authnRequest->getAssertionConsumerServiceURL()])
              )
      )// Ορίζουμε διάφορες παραμέτρους όπως πότε δημιουγήθηκε η απάντηση
      ->addItem(
          (new \LightSaml\Model\Assertion\AttributeStatement())
              ->addAttribute(new \LightSaml\Model\Assertion\Attribute(\LightSaml\ClaimTypes::EMAIL_ADDRESS, $_SESSION['user']))// Το email του χρήστη
              ->addAttribute(new \LightSaml\Model\Assertion\Attribute(\LightSaml\ClaimTypes::COMMON_NAME, 'x123')) // Το όνομά του
      )// Σαφώς μπορούν να οριστούν επιπλέον πληροφορίες που μπορεί να ζητήσει ο περιφερειακός οργανιμός απο τον κεντρικό.
      ->addItem(
          (new \LightSaml\Model\Assertion\AuthnStatement())
              ->setAuthnInstant(new \DateTime('-10 MINUTE'))
              ->setSessionIndex('_some_session_index')
              ->setAuthnContext(
                  (new \LightSaml\Model\Assertion\AuthnContext())
                      ->setAuthnContextClassRef(\LightSaml\SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
              )
      ); //Εδώ ορίζουμε τη διάρκεια της σύνδεσης 
        $certificate = \LightSaml\Credential\X509Certificate::fromFile('ssl/cert.crt'); // Χρησιμοοπιώντας τα κλειδιά κρυπτογραφούμε τα δεδομένα που θα στείλουμε πίσω
        $privateKey = \LightSaml\Credential\KeyHelper::createPrivateKey('ssl/pkey.key', '', true);
        
        $encryptedAssertion = new \LightSaml\Model\Assertion\EncryptedAssertionWriter();
        $encryptedAssertion->encrypt($assertion, \LightSaml\Credential\KeyHelper::createPublicKey($certificate));// Κρυτπογραφούμε τα αντικείμενα.
        $response = new \LightSaml\Model\Protocol\Response();// Φτιάχνουμε το αντικείμενο της απάντησης
        $response->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter($certificate, $privateKey)); //Το υπογράφουμε
        $response
            ->addEncryptedAssertion($encryptedAssertion)
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($authnRequest->getAssertionConsumerServiceURL()) // Ορίζουμε το url απο θα ανακατευθύνουμε τον χρήστη
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer('http://idp.teo.com'));
  
            $bindingFactory = new \LightSaml\Binding\BindingFactory();
            $postBinding = $bindingFactory->create(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST);
            $messageContext = new \LightSaml\Context\Profile\MessageContext();// Εδώ δημιουργείται το πακέτο ανακατεύθυνσης του χρήστη στον περιφερειακό οργανισμό, το πακέτο της απάντησης
            // θα σταλεί με HTTP Post 
            $messageContext->setMessage($response);
            //var_dump($messageContext);exit;
            $httpResponse = $postBinding->send($messageContext);
            print $httpResponse->getContent();
}


function checkSignature($request){
    $decoded = str_replace(" ","+",$request);
    $xml = base64_decode($decoded);
    //var_dump($decoded);exit;
    //$xml = $decoded;//gzinflate($decoded);
    $key = \LightSaml\Credential\KeyHelper::createPublicKey(
        \LightSaml\Credential\X509Certificate::fromFile('ssl/cert.crt')
    );
    $deserializationContext = new \LightSaml\Model\Context\DeserializationContext();
    $deserializationContext->getDocument()->loadXML($xml);
    $authnRequest = new \LightSaml\Model\Protocol\AuthnRequest();
    //echo "AuthRequest passed";
    $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);

    /** @var \LightSaml\Model\XmlDSig\SignatureXmlReader $signatureReader */
    $signatureReader = $authnRequest->getSignature();

    try {
        $ok = $signatureReader->validate($key);

        if ($ok) {
            print "Signature OK\n";
            return true;
        } else {
            print "Signature not validated";
        }
    } catch (\Exception $ex) {
        print "Signature validation failed\n";
    }
    return false;
}