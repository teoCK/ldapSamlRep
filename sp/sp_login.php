<?php
require "vendor/autoload.php";//με αυτόν τον τρόπο φορτώνουμε όλα τις εξωτερικές βιβλιοθήκες μέσα απο το vendor. Τα αρχεία μας δεν γνωρίζουν την ύπαρξη αυτών των βιβλιοθηκών, αν δεν τις βάλουμε μέσα με κάποια εντολή require. 

$authnRequest = new \LightSaml\Model\Protocol\AuthnRequest();
$authnRequest
    ->setAssertionConsumerServiceURL('http://192.168.1.25/index.php')
    ->setProtocolBinding(\LightSaml\SamlConstants::BINDING_SAML2_HTTP_POST)
    ->setID(\LightSaml\Helper::generateID())
    ->setIssueInstant(new \DateTime())
    ->setDestination('http://192.168.1.14/index.php')
    ->setIssuer(new \LightSaml\Model\Assertion\Issuer('http://idp.teo.com'));
    //var_dump($authnRequest);
    $serializationContext = new \LightSaml\Model\Context\SerializationContext();

    $authnRequest->serialize($serializationContext->getDocument(), $serializationContext);
    
    //var_dump($serializationContext->getDocument()->saveXML());
?>
<a class="btn" href="http://192.168.1.14/index.php?SAMLRequest=<?=base64_encode($serializationContext->getDocument()->saveXML())?>">Login via SAML</a>