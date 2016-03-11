<?php

namespace Clef;

trait Signing {

    private static $DIGEST_ALG = 'SHA256';
    private static $SIGNATURE_ALG = OPENSSL_ALGO_SHA256;

    function sign_payload($payload = array()) {
        $payload = $this->add_keys_to_payload($payload);

        $payload_json = $this->sort_and_json_encode($payload);
        $payload_hash = $this->hash($payload_json);
        $payload_signature = $this->sign($payload_json, $this->configuration->getKeypair());

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

    public function assert_signatures_present($payload, $signature_types) {
        if (!isset($payload["signatures"])) {
            throw new InvalidPayloadError("No signatures provided");
        }

        $signatures = $payload["signatures"];
        foreach ($signature_types as $type) {
            $is_present = isset($signatures[$type]) && isset($signatures[$type]["signature"]);

            if (!$is_present) {
                throw new InvalidPayloadError("No " . $type . " signature provided");
            }
        }

        return true;
    }

    public function assert_test_payload($payload) {
        $payload_blob = json_decode($payload["payload_json"], true);
        if (!array_key_exists('test', $payload_blob)) {
            throw new InvalidPayloadError("Missing 'test' key for test payloads.");
        }

        if (!isset($payload_blob['test'])) {
            throw new VerificationError("Invalid test payload.");
        }

        return true;
    }

    public function assert_payload_hash_valid($payload) {
        if (!isset($payload["payload_json"]) || $payload["payload_json"] === "") {
            throw new InvalidPayloadError("Missing payload_json");
        }

        if (!isset($payload["payload_hash"]) || $payload["payload_hash"] === "") {
            throw new InvalidPayloadError("Missing payload_hash");
        }

        $computed_payload_hash = $this->hash($payload["payload_json"]);
        $provided_payload_hash = $payload["payload_hash"];

        if ($computed_payload_hash != $provided_payload_hash) {
            throw new InvalidPayloadHashError("payload_hash does not match payload_json");
        }

        return true;
    }

    public function assert_signature_valid($payload, $signature_type, $public_key) {
        $signature_is_valid = $this->verify(
            $payload["payload_json"],
            $this->base64url_decode($payload["signatures"][$signature_type]["signature"]),
            $public_key
        );

        if (!$signature_is_valid) {
            throw new BadSignatureError("Invalid signature for " . $signature_type);
        }

        return true;
    }

    /* Private functions */

    function assert_keys_in_payload($payload, $keys) {
        foreach ($keys as $key) {
            if (!isset($payload[$key])) {
                throw new \Clef\InvalidPayloadError("Missing " . $key . " in payload.");
            }
        }
    }

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

    function sign($data, $keypair) {
        openssl_sign($data, $signature, $keypair, self::$SIGNATURE_ALG);
        return $signature;
    }

    function verify($data, $signature, $public_key) {
        if (is_string($public_key)) {
            $public_key = openssl_get_publickey($public_key);
        }

        $return_code = openssl_verify($data, $signature, $public_key, self::$SIGNATURE_ALG);
        if ($return_code === 1) {
            return true;
        } else if ($return_code === 0) {
            return false;
        } else if ($return_code === -1) {
            throw new VerificationError("There was an error verifying the signature");
        }
    }
}
