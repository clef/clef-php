<?php

namespace Clef;

use Exception;

class Error extends Exception {}

class InvalidAppIDError extends Error {}
class InvalidAppSecretError extends Error {}
class InvalidAppError extends Error {}
class InvalidOAuthCodeError extends Error {}
class InvalidOAuthTokenError extends Error {}
class InvalidLogoutHookURLError extends Error {}
class InvalidLogoutTokenError extends Error {}
class ServerError extends Error {}
class ConnectionError extends Error {}

class Clef {

    // @var string The Stripe API key to be used for requests.
    public static $apiID;
    public static $apiSecret;

    // @var string The base URL for the Stripe API.
    public static $apiBase = 'https://clef.io/api';
    // @var string|null The version of the Clef API to use for requests.
    public static $apiVersion = 'v1';

    const VERSION = '1.0.1';

    /**
     * @return string The API ID used for requests.
     */
    public static function getApiID() {
        return self::$apiID;
    }

    /**
     * @return string The API Secret used for requests.
     */
    public static function getApiSecret() {
        return self::$apiSecret;
    }

    /**
     * Sets the API key to be used for requests.
     *
     * @param string $apiKey
     */
    public static function initialize($apiID, $apiSecret) {
        self::$apiID = $apiID;
        self::$apiSecret = $apiSecret;
    }

    /**
     * @return string The API version used for requests. null if we're using the
     *    latest version.
     */
    public static function getApiVersion() {
        return self::$apiVersion;
    }

    /**
     * @param string $apiVersion The API version to use for requests.
     */
    public static function setApiVersion($apiVersion) {
        self::$apiVersion = $apiVersion;
    }

    private static function doApiRequest($path, $options=array(method => 'POST')) {
        switch ($options['method']) {
            case "POST":
                $requestOptions = array('http' =>
                    array(
                        'method'  => 'POST',
                        'header'  => 'Content-type: application/x-www-form-urlencoded',
                        'ignore_errors' => true
                    )
                );

                if (isset($options['data'])) {
                    $requestOptions['http']['content'] = http_build_query($options['data']);
                }

                break;
            case "GET":
                $requestOptions = array('http' =>
                    array(
                        'method'  => 'GET',
                        'ignore_errors' => true
                    )
                );

                if (isset($options['data'])) {
                    $path .= '?' . http_build_query($options['data']);
                }

                break;
            default:
                throw new Exception("Invalid Clef API request method.");
        }

        $url = self::$apiBase . '/' . Clef::getApiVersion() . $path;
        $response = @file_get_contents($url, false, stream_context_create($requestOptions));

        if ($response !== false) {
            try {
                return json_decode($response);
            } catch (Exception $e) {
                throw new ServerError("An error occurred while processing your Clef API request: " . $response);
            }
        } else {
            throw new ConnectionError("An error occurred while trying to connect to the Clef API. Please check your connection and try again.");
        }
    }

    public static function get_login_information($code) {
        if (!isset($code) || trim($code) === "") {
            throw new InvalidOAuthCodeError();
        }

        $response = Clef::doApiRequest(
            "/authorize",
            array(
                "data" => array(
                    'code' => $code,
                    'app_id' => Clef::getApiID(),
                    'app_secret' => Clef::getApiSecret()
                ),
                "method" => 'POST'
            )
        );

        // if there's an error, Clef's API will report it
        if(!isset($response->error)) {
            $response = Clef::doApiRequest(
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
                self::message_to_error($response->error);
            }
        } else {
            self::message_to_error($response->error);
        }
    }

    public static function get_logout_information($token) {
        if (!isset($token) || trim($token) === "") {
            throw new InvalidLogoutTokenError();
        }

        $response = Clef::doApiRequest(
            '/logout',
            array(
                "data" => array(
                    "logout_token" => $token,
                    "app_id" => Clef::getApiID(),
                    "app_secret" => Clef::getApiSecret()
                ),
                "method" => 'POST'
            )
        );

        if (!isset($response->error)) {
            return $response->clef_id;
        } else {
            self::message_to_error($response->error);
        }
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


    private static function message_to_error($msg) {
        switch ($msg) {
            case "Invalid App ID.":
                throw new InvalidAppIDError("The application ID you provided is invalid.");
                break;
            case "Invalid App Secret.":
                throw new InvalidAppSecretError("The application secret you provided is invalid.");
                break;
            case "Invalid App.":
                throw new InvalidAppError("The application ID or secret you provided is invalid.");
                break;
            case "Invalid OAuth Code.":
                throw new InvalidOAuthCodeError("The OAuth code you provided is invalid.");
                break;
            case "Invalid token.":
                throw new InvalidOAuthTokenError("The OAuth token returned by the Clef API is invalid.");
                break;
            case "Invalid logout hook URL.":
                throw new InvalidLogoutHookURLError("The custom logout hook URL you provided is invalid. Please verify that it is on the same domain as your application.");
                break;
            case "Invalid Logout Token.":
                throw new InvalidLogoutTokenError("The logout token you provided is invalid.");
                break;
            default:
                throw new Exception("An exception occurred while accessing the Clef API: " . $msg);
        }
    }

    private static function base64url_encode($plainText) {
        $base64 = base64_encode($plainText);
        $base64url = strtr($base64, '+/=', '-_,');
        return $base64url;
    }
}