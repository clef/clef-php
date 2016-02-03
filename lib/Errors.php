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

trait Errors {
    private function message_to_error($msg) {
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
}
