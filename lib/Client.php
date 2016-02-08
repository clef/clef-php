<?php

namespace Clef;

require_once __DIR__ . "/Encoding.php";
require_once __DIR__ . "/Signing.php";
require_once __DIR__ . "/Errors.php";
require_once __DIR__ . "/Requests.php";

class Client {
    use \Clef\Encoding;
    use \Clef\Signing;
    use \Clef\Requests;
    use \Clef\Errors;

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

        $response = $this->doApiRequest(
            "/authorize",
            array(
                "data" => array(
                    'code' => $code,
                    'app_id' => $this->configuration->id,
                    'app_secret' => $this->configuration->secret
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
                    'app_id' => $this->configuration->id,
                    'app_secret' => $this->configuration->secret
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

    public function generate_session_state_parameter() {
        if (!session_id()) {
            session_start();
        }

        if (isset($_SESSION['state'])) {
            return $_SESSION['state'];
        } else {
            $state = $this->base64url_encode(openssl_random_pseudo_bytes(32));
            $_SESSION['state'] = $state;
            return $state;
        }
    }

    public static function validate_session_state_parameter($state) {
        if (!session_id()) {
            session_start();
        }

        $is_valid = isset($_SESSION['state']) && strlen($_SESSION['state']) > 0 && $_SESSION['state'] == $state;
        unset($_SESSION['state']);
        return $is_valid;
    }
} 
