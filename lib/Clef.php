<?php

namespace Clef;

class ClefAPIError extends Exception {}

class ClefAPIInvalidAppIDError extends ClefAPIError {}
class ClefAPIInvalidAppSecretError extends ClefAPIError {}
class ClefAPIInvalidAppError extends ClefAPIError {}
class ClefAPIInvalidOAuthCodeError extends ClefAPIError {}
class ClefAPIInvalidOAuthTokenError extends ClefAPIError {}
class ClefAPIInvalidLogoutHookURLError extends ClefAPIError {}
class ClefAPIInvalidLogoutTokenError extends ClefAPIError {}
class ClefAPIServerError extends ClefAPIError {}
class ClefAPIConnectionError extends ClefAPIError {}

class Clef {

    private static $MESSAGE_TO_ERROR_MAP = [
        'Invalid App ID.' => ClefAPIInvalidAppIDError,
        'Invalid App Secret.' => ClefAPIInvalidAppSecretError,
        'Invalid App.' => ClefAPIInvalidAppError,
        'Invalid OAuth Code.' => ClefAPIInvalidOAuthCodeError,
        'Invalid token.' => ClefAPIInvalidOAuthTokenError,
        'Invalid logout hook URL.' => ClefAPIInvalidLogoutHookURLError,
        'Invalid Logout Token.' => ClefAPIInvalidLogoutTokenError,
    ];

    // @var string The Stripe API key to be used for requests.
    public static $apiID;
    public static $apiSecret;

    // @var string The base URL for the Stripe API.
    public static $apiBase = 'https://clef.io/api';
    // @var string|null The version of the Clef API to use for requests.
    public static $apiVersion = 'v1';

    const VERSION = '0.0.1';

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
                throw new ClefAPIServerError("An error occurred while processing your Clef API request: " . $response);
            }
        } else {
            throw new ClefAPIConnectionError("An error occurred while trying to connect to the Clef API. Please check your connection and try again.");
        }
    }

    public static function get_login_information($code) {
        if (!(isset($_REQUEST['state']) && Clef::validate_state_parameter($_REQUEST['state']))) {
            header('HTTP/1.0 403 Forbidden');
            echo "The state parameter didn't match what was passed in to the Clef button.";
            exit;
        }

        if (!isset($code) || trim($code) === "") {
            throw new ClefAPIInvalidOAuthCodeError();
        }

        $response = Clef::doApiRequest(
            "/authorize",
            array(
                data => array(
                    'code' => $code,
                    'app_id' => Clef::getApiID(),
                    'app_secret' => Clef::getApiSecret()
                ),
                method => 'POST'
            )
        );

        // if there's an error, Clef's API will report it
        if(!$response->error) {
            $response = Clef::doApiRequest(
                "/info",
                array(
                    data => array(
                        access_token => $response->access_token
                    ),
                    method => "GET"
                )
            );

            if (!isset($response->error)) {
                return $response;
            } else {
                throw new Clef::$MESSAGE_TO_ERROR_MAP($response->error);
            }
        } else {
            throw new Clef::$MESSAGE_TO_ERROR_MAP[$response->error];
        }


    }

    public static function get_logout_information($token) {
        if (!isset($token) || trim($token) === "") {
            throw new ClefEmptyLogoutTokenException();
        }

        $response = Clef::doApiRequest(
            '/logout',
            array(
                data => array(
                    logout_token => $token,
                    app_id => Clef::getApiID(),
                    app_secret => Clef::getApiSecret()
                ),
                method => 'POST'
            )
        );

        if (!$response->error) {
            return $response->clef_id;
        } else {
            throw new Clef::$MESSAGE_TO_ERROR_MAP[$response->error];
        }
    }

    private static function base64url_encode($plainText) {
        $base64 = base64_encode($plainText);
        $base64url = strtr($base64, '+/=', '-_,');
        return $base64url;
    }

    public static function generate_state_parameter() {
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

    public static function validate_state_parameter($state) {
        if (!session_id()) {
            session_start();
        }

        $is_valid = isset($_SESSION['state']) && strlen($_SESSION['state']) > 0 && $_SESSION['state'] == $state;
        unset($_SESSION['state']);
        return $is_valid;
    }
}