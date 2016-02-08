<?php

namespace Clef;

class Configuration {

    public $id;
    public $secret;
    public $passphrase;
    public $keypair;

    public $api_base = "https://clef.io";
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

    function getKeypairObject() {
        if (!isset($this->keypair)) {
            throw new \Clef\MisconfigurationError("Please set a keypair on the Clef configuration object");
        }

        if (is_string($this->keypair)) {
            return openssl_get_private($this->keypair);
        }

        return $this->keypair;
    }

    function getPublicKey() {
        if (!isset($this->_public_key)) {
            $this->_public_key = openssl_get_publickey(openssl_pkey_get_details($this->getKeypairObject())['key']); 
        }
        return $this->_public_key;
    }
}
