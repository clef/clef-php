<?php

namespace Clef;

class Configuration {

    public $id;
    public $secret;
    public $passphrase;

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
}
