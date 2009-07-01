<?php

require_once 'lib/SignedRequestValidator.php';

$validator = new SignedRequestValidator('http://devlab.agektmr.com/SignedRequest/SignedRequest.xml');
$validator->validate_request();

echo "succeed";

?>
