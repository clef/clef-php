<?php

namespace Clef;

require_once __DIR__ . '/Configuration.php';
require_once __DIR__ . '/Client.php';
require_once __DIR__ . '/Errors.php';

class Clef {

    // @var string The Stripe API key to be used for requests.
    public static $apiID;
    public static $apiSecret;

    // @var string The base URL for the Stripe API.
    public static $apiBase = 'https://clef.io/api';
    // @var string|null The version of the Clef API to use for requests.
    public static $apiVersion = 'v1';

    private static $configuration;
    private static $client;

    const VERSION = '1.0.1';

    /**
     * @return string The API ID used for requests.
     */
    public static function getApiID() {
        return self::$configuration->id;
    }

    /**
     * @return string The API Secret used for requests.
     */
    public static function getApiSecret() {
        return self::$configuration->secret;
    }

    /**
     * @return string The API version used for requests. null if we're using the
     *    latest version.
     */
    public static function getApiVersion() {
        return self::$configuration->api_version;
    }

    /**
     * @param string $apiVersion The API version to use for requests.
     */
    public static function setApiVersion($api_version) {
        self::$configuration->api_version = $api_version;
    }

    /**
     * Sets the API key to be used for requests.
     *
     * @param string $apiKey
     */
    public static function initialize($id, $secret, $configuration = null) {
        if (!isset($configuration)) {
            $configuration = new \Clef\Configuration(array(
                "id" => $id,
                "secret" => $secret
            ));
        }

        self::$configuration = $configuration;
        self::$client = new \Clef\Client(self::$configuration);
    }

    public static function get_login_information($code) {
        return self::$client->get_login_information($code);
    }

    public static function get_logout_information($token) {
        return self::$client->get_logout_information($token);
    }

    public static function generate_session_state_parameter() {
        if (!session_id()) {
            session_start();
        }

        if (isset($_SESSION['state'])) {
            return $_SESSION['state'];
        } else {
            $state = Clef::base64url_encode(openssl_random_pseudo_bytes(32));
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

    private static function base64url_encode($plainText) {
        $base64 = base64_encode($plainText);
        $base64url = strtr($base64, '+/=', '-_,');
        return $base64url;
    }
}
