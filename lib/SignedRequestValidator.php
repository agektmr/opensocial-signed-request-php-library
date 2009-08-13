<?php

require_once 'publickeys.php';
require_once 'OAuth.php';

class ServerSignatureMethod extends OAuthSignatureMethod_RSA_SHA1 {
  public $cert;
  protected function fetch_public_cert(&$request) {
    return $this->cert;
  }
  public function set_public_cert($consumerKey) {
    global $publickeys;
    if ($publickeys[$consumerKey]) {
      $this->cert = $publickeys[$consumerKey]['publickey'];
      return true;
    } else {
      return false;
    }
  }
}

class SignedRequestValidator {
  private $oauth_consumer_key;
  private $oauth_signature;
  private $gadget_url;
  private $opensocial_app_url;

  function __construct($gadget_url='') {
    $this->gadget_url         = $gadget_url;
    $this->opensocial_app_url = $_GET['opensocial_app_url'];
    $this->oauth_consumer_key = $_GET['oauth_consumer_key'];
    $this->oauth_signature    = $_GET['oauth_signature'];
  }
  public function validate_request() {
    $result = true;
    // Is gadget_url specified?
    if (sizeof($this->gadget_url) > 0) {
      // Does gadget_url match opensocial_app_id?
      if ($this->opensocial_app_url != $this->gadget_url) {
        $result = false;
      }
    }
    // Is this a signed request?
    if (!empty($this->oauth_consumer_key) && !empty($this->oauth_signature)) {
      $request = OAuthRequest::from_request(null, null, array_merge($_GET, $_POST));
      $signature_method = new ServerSignatureMethod();
      $signature_method->set_public_cert($this->oauth_consumer_key);
      // See if signature is valid
      if (!$signature_method->check_signature($request, null, null, $this->oauth_signature)) {
        $result = false;
      }
    }
    // If invalid request, return HTTP 401 response
    if (!$result) {
      header("HTTP/1.0 401 Unauthorized", true, 401);
      echo "<html><body>401 Unauthorized</body></html>";
      die();
    }
    // If valid request, go forward
    return true;
  }
}

?>
