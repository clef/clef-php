<?php

namespace Clef;

class Configuration {

    public $id;
    public $secret;
    public $passphrase = "";
    public $keypair;

    public $api_base = "https://clef.io/api";
    public $api_version = "v1";
    public $debug = false;

    public $initiation_public_key;
    public $confirmation_public_key;

    function __construct($args) {
        foreach ($this as $key => $value) {
            if (isset($args[$key])) {
                $this->$key = $args[$key];
            }
        }
    }

    function getKeypair() {
        if (!isset($this->_keypair)) {
            if (is_string($this->keypair)) {
                $this->_keypair = openssl_get_privatekey($this->keypair, $this->passphrase);
            } else if (is_resource($this->keypair)) {
                $this->_keypair = $this->keypair;
            }
        }

        if (isset($this->_keypair) && $this->_keypair != "") {
            return $this->_keypair;
        } else {
            throw new \Clef\MisconfigurationError("Please set a keypair on the Clef configuration object. This can either be a string of the PEM formatted private key or a path to the file in the form file:///home/user/path/to/private.pem.");
        }
    }

    function getPublicKey() {
        if (!isset($this->_public_key)) {
            $this->_public_key = openssl_get_publickey(openssl_pkey_get_details($this->getKeypair())['key']); 
        }
        return $this->_public_key;
    }
}
