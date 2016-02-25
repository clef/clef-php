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
        $this->assert_keys_in_payload($payload, array("reactivation_token"));
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

    public function verify_reactivation_payload($payload, $options = array()) {
      $this->assert_payload_hash_valid($payload);
      $this->assert_signatures_present($payload, array("initiation"));
      $this->assert_signature_valid($payload, "initiation", $this->configuration->initiation_public_key);

      $is_test_reactivation = isset($options['unsafe_do_not_verify_confirmation_signature']) &&
          $options['unsafe_do_not_verify_confirmation_signature'] == 1;

      if ($is_test_reactivation){
        $this->assert_test_payload($payload);
      } else {
        $this->assert_signatures_present($payload, array("confirmation"));
        $this->assert_signature_valid($payload, "confirmation", $this->configuration->confirmation_public_key);
      }

      return true;
    }

    public function get_reactivation_payload($token, $options = array()) {
      $reactivation_handshake_payload = array("reactivation_token" => $token);
      $signed_reactivation_handshake_payload = $this->sign_reactivation_payload($reactivation_handshake_payload);
      $encoded_reactivation_handshake_payload = $this->encode_payload($signed_reactivation_handshake_payload);

      $reactivation_payload = $this->get(
        "reactivations/$token", array(),
        array(
              "Authorization" => "Payload $encoded_reactivation_handshake_payload"
        )
      );

      $this->verify_reactivation_payload($reactivation_payload, $options);
      $payload = json_decode($reactivation_payload["payload_json"], true);
      return $payload;
    }

    public function get_login_information($code) {
        if (!isset($code) || trim($code) === "") {
            throw new InvalidOAuthCodeError();
        }

        $auth_response = $this->post(
            "authorize",
            array(
                'code' => $code,
                'app_id' => $this->configuration->id,
                'app_secret' => $this->configuration->secret
            )
        );

        // if there's an error, Clef's API will report it
        if(!isset($auth_response["error"])) {
            $info_response = $this->get(
                "info",
                array(
                    "access_token" => $auth_response["access_token"]
                )
            );

            if (!isset($info_response["error"])) {
                return $info_response;
            } else {
                $this->message_to_error($info_response["error"]);
            }
        } else {
            $this->message_to_error($auth_response["error"]);
        }
    }

    public function get_logout_information($token) {
        if (!isset($token) || trim($token) === "") {
            throw new InvalidLogoutTokenError();
        }

        $response = $this->post(
            'logout',
            array (
                    "logout_token" => $token,
                    'app_id' => $this->configuration->id,
                    'app_secret' => $this->configuration->secret
            )
        );

        if (!isset($response["error"])) {
            return $response["clef_id"];
        } else {
            $this->message_to_error($response["error"]);
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
