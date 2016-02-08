<?php

namespace Clef;

require_once __DIR__ . "/Encoding.php";
require_once __DIR__ . "/Signing.php";

class Client {
    use \Clef\Encoding;
    use \Clef\Signing;

    private $configuration;

    function __construct($configuration) {
        $this->configuration = $configuration;
    }

    public function sign_login_payload($payload) {
        $payload["type"] = "login";
        $this->assert_keys_in_payload($payload, array("clef_id", "nonce", "redirect_url", "session_id", "type"));
        return $this->sign_payload($payload);
    }

    public function sign_reactivation_payload($payload) {
        $payload["type"] = "reactivation_handshake";
        $this->assert_keys_in_payload($payload, array("type"));
        return $this->sign_payload($payload);
    }

    public function verify_login_payload($payload, $user_public_key) {
        if (is_string($user_public_key)) {
            $user_public_key = openssl_get_public($user_public_key);
        }

        $this->assert_payload_hash_valid($payload);
        $this->assert_signatures_present($payload, array("application", "user"));
        $this->assert_signature_valid($payload, "application", $this->configuration->getPublicKey());
        $this->assert_signature_valid($payload, "user", $user_public_key);

        return true;
    }

    public function encode_payload($payload) {
        return $this->base64url_encode(json_encode($payload));
    }

    public function decode_payload($payload) {
        return json_decode($this->base64url_decode($payload), true);
    }

    public function get_login_information($code) {
        if (!isset($code) || trim($code) === "") {
            throw new InvalidOAuthCodeError();
        }

        $response = Clef::doApiRequest(
            "/authorize",
            array(
                "data" => array(
                    'code' => $code,
                    'app_id' => $this->$configuration->$id,
                    'app_secret' => $this->$configuration->$secret
                ),
                "method" => 'POST'
            )
        );

        // if there's an error, Clef's API will report it
        if(!isset($response->error)) {
            $response = $this->doApiRequest(
                "/info",
                array(
                    "data" => array(
                        "access_token" => $response->access_token
                    ),
                    "method" => "GET"
                )
            );

            if (!isset($response->error)) {
                return $response;
            } else {
                $this->message_to_error($response->error);
            }
        } else {
            $this->message_to_error($response->error);
        }
    }

    public function get_logout_information($token) {
        if (!isset($token) || trim($token) === "") {
            throw new InvalidLogoutTokenError();
        }

        $response = $this->doApiRequest(
            '/logout',
            array(
                "data" => array(
                    "logout_token" => $token,
                    'app_id' => $this->$configuration->$id,
                    'app_secret' => $this->$configuration->$secret
                ),
                "method" => 'POST'
            )
        );

        if (!isset($response->error)) {
            return $response->clef_id;
        } else {
            $this->message_to_error($response->error);
        }
    }
} 
