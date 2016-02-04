<?php

namespace Clef;

trait Signing {

    private static $DIGEST_ALG = 'SHA256';
    private static $SIGNATURE_ALG = OPENSSL_ALGO_SHA256;

    function sign_payload($payload = array()) {
        $payload = $this->add_keys_to_payload($payload);

        $payload_json = $this->sort_and_json_encode($payload);
        $payload_hash = $this->hash($payload_json);
        $payload_signature = $this->sign($payload_json);

        return $this->sort(array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash,
            "signatures" => array(
                "application" => array(
                    "signature" => $this->strict_base64_encode($payload_signature),
                    "type" => "rsa-sha256"
                )
            )
        ));
    }

    /* Private functions */ 

    function add_keys_to_payload($payload) {
        $payload["application_id"] = $this->configuration->id;
        $payload["timestamp"] = time();
        return $payload;
    }

    function sort($arr) {
        ksort($arr);
        return $arr;
    }

    function sort_and_json_encode($arr) {
        ksort($arr);
        return json_encode($arr);
    }

    function strict_base64_encode($data) {
        return base64_encode($data);
    }

    function hash($data) {
        return openssl_digest($data, self::$DIGEST_ALG); 
    }

    function sign($data) {
        openssl_sign($data, $signature, $this->configuration->getKeypairObject(), self::$SIGNATURE_ALG);
        return $signature;
    }


}
