<?php

namespace Clef;

require_once __DIR__ . '/Configuration.php';
require_once __DIR__ . '/Client.php';
require_once __DIR__ . '/Errors.php';

class Clef {
    private static $configuration;
    private static $client;

    const VERSION = '2.0.0';

    public static function configure($configuration) {
        self::$configuration = $configuration;
        self::$client = new \Clef\Client(self::$configuration);
    }

    public static function get_login_information($code) {
        self::assert_configured();
        return self::$client->get_login_information($code);
    }

    public static function get_logout_information($token) {
        self::assert_configured();
        return self::$client->get_logout_information($token);
    }

    public static function generate_session_state_parameter() {
        self::assert_configured();
        return self::$client->generate_session_state_parameter();
    }

    public static function sign_login_payload($payload) {
        self::assert_configured();
        return self::$client->sign_login_payload($payload);
    }

    public static function sign_reactivation_payload($payload) {
        self::assert_configured();
        return self::$client->sign_reactivation_payload($payload);
    }

    public static function verify_login_payload($payload, $user_public_key) {
        self::assert_configured();
        return self::$client->verify_login_payload($payload, $user_public_key);
    }

    public static function encode_payload($payload) {
        return self::$client->encode_payload($payload);
    }

    public static function decode_payload($payload) {
        return self::$client->decode_payload($payload);
    }

    public static function validate_session_state_parameter($state) {
        return self::$client->validate_session_state_parameter($state);
    }

    private static function assert_configured() {
        if (!(isset(self::$client) && isset(self::$configuration))) {
            throw new MisconfigurationError("You have not configured Clef. Please call \Clef\Clef::\$configure before using the library.");
        }
    }

    // Deprecated functions

    /**
     * @deprecated
     * @return string The API ID used for requests.
     */
    public static function getApiID() {
        return self::$configuration->id;
    }

    /**
     * @deprecated
     * @return string The API Secret used for requests.
     */
    public static function getApiSecret() {
        return self::$configuration->secret;
    }

    /**
     * @deprecated
     * @return string The API version used for requests. null if we're using the
     *    latest version.
     */
    public static function getApiVersion() {
        return self::$configuration->api_version;
    }

    /**
     * @deprecated
     * @param string $apiVersion The API version to use for requests.
     */
    public static function setApiVersion($api_version) {
        self::$configuration->api_version = $api_version;
    }

    /**
     * Sets the API key to be used for requests.
     * 
     * @deprecated
     * @param string $apiKey
     */
    public static function initialize($id, $secret) {
        $configuration = new \Clef\Configuration(array(
            "id" => $id,
            "secret" => $secret
        ));
        self::configure($configuration);
    }
}
