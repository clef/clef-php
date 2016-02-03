<?php

namespace Clef;

class Client {
    private $configuration;

    function __construct($configuration) {
        $this->configuration = $configuration;
    }

    public function sign_login_payload($payload) {
        return $payload;
    }

    public function verify_login_payload($payload, $user_public_key) {
        return true;
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
