# Clef PHP bindings

[![Latest Stable Version](https://poser.pugx.org/clef/clef-php/v/stable.svg)](https://packagist.org/packages/clef/clef-php)
[![License](https://poser.pugx.org/clef/clef-php/license.svg)](https://packagist.org/packages/clef/clef-php)

A PHP wrapper for the [Clef](https://getclef.com/) API. Authenticate a user and access their information in two lines of code. 

You can sign up for a Clef account at https://getclef.com.

## Requirements

PHP 5.3.3 and later.

## Composer

You can install the bindings via [Composer](http://getcomposer.org/). Add this to your `composer.json`:

    {
      "require": {
        "clef/clef-php": "1.*"
      }
    }

Then install via:

    composer install

To use the bindings, use Composer's [autoload](https://getcomposer.org/doc/00-intro.md#autoloading):

    require_once('vendor/autoload.php');

## Manual Installation

If you do not wish to use Composer, you can download the [latest release](https://github.com/clef/clef-php/releases). Then, to use the bindings, include the `init.php` file.

    require_once('/path/to/clef-php/init.php');


Usage
-----

#### Configuring the library

You'll need to configure the PHP library with your app ID and app secret. If you're using Distributed Auth, you'll also need to configure it with your private key and optionally the passphrase used to protect it. 

    $configuration = new \Clef\Configuration(array(
        "id" => "YOUR_APPLICATION_ID", 
        "secret" => "YOUR_APPLICATION_SECRET", 
        "keypair" => __DIR__ . "yourprivatekey.pem",
        "passphrase" => "optional passphrase used to encrypt your key"
    ));
    \Clef\Clef::configure($configuration);

*id* is your website's app ID, which you generated in the Clef dashboard when you created your integration. 

*secret* is your website's app ID, which you generated in the Clef dashboard when you created your integration. 

*keypair* is either the path to your PEM-formatted private key or aa string representation of your keypair's PEM-formatted private key. Your private key may be encrypted if you set a passphrase when you generated your keypair. 

*passphrase* (optional) is an optional passphrase that protects your website's keypair. You can set a passphrase when you generate your keypair using ssh-keygen or openssl. 

#### Logging in a user

When a user logs in with Clef, the browser will redirect to your `data-redirect-url`. To retrieve user information, call `get_login_information` in that endpoint: 

    \Clef\Clef::configure($configuration);
    $response = \Clef\Clef::get_login_information($_GET["code"]);

For what to do after getting user information, check out our documentation on
[Associating users](http://docs.getclef.com/v1.0/docs/persisting-users).

#### Logging out a user

When you configure your Clef integration, you can also set up a logout hook URL. Clef sends a POST to this URL whenever a user logs out with Clef, so you can log them out on your website too.

    \Clef\Clef::configure($configuration);
    $clef_id = \Clef\Clef::get_logout_information($_POST["logout_token"]);

For what to do after getting a user who's logging out's `clef_id`, see our
documentation on [Database
logout](http://docs.getclef.com/v1.0/docs/database-logout).

## Distributed Auth

The Clef PHP library can be used to implement [Distributed Auth](https://getclef.com/distributed). If you're not using Distributed Auth, please ignore this section.

#### Constructing the login payload

After you complete the OAuth handshake, the library will construct, sign, and serialize a valid payload for you.

First, construct the payload: 

    // Following the OAuth handshake, we create or look up a user with the
    // information returned by Clef. Since auth_hash contains a user's public key,
    // a newly created user should be created with the public key.
    $user = User::find_by_clef_id($response["clef_id"]);

    $payload = array(
        "nonce" => bin2hex(openssl_random_pseudo_bytes(16)),
        "clef_id" => $user->clef_id,
        "redirect_url" => 'http://yourwebsite.com/clef/confirm',
        "session_id" => $session_id
    }

    # We store the payload in the browser session so we can verify the nonce later
    $_SESSION['clef_payload'] = $payload;

You can then sign the payload: 

    $signed_payload = \Clef\Clef::sign_login_payload($payload);

The Clef library will take care of properly serializing the payload to `payload_json`, generating a `SHA256` hash and signing it. 

Finally, you can serialize the payload to base64 and redirect the browser: 

    header("https://clef.io/api/v1/validate?payload=" . \Clef\Clef::encode_payload(signed_payload));
    die();

#### Verifying the user-signed payload after a user confirms login

When the browser redirects to your distributed validation `redirect_url`, you'll receive the payload bundle you sent to Clef, signed by the user. We can use the library to validate and verify the user's signature.

First, we decode the payload and check it against the nonce we generated: 

    $payload_bundle = Clef::decode_payload($_REQUEST["payload"]);
    $signed_payload = json_decode(payload_bundle["payload_json"], true);

    $session_payload = $_SESSION["clef_payload"];
    $payload_is_valid = ($session_payload != "" && $signed_payload != "" and $session_payload["nonce"] === $signed_payload["nonce"]);

    if ($payload_is_valid) {
        unset($_SESSION["clef_payload"]);
    } else {
        // Show an error message to the user
    }

Then, we verify that the payload is signed by the user's private key: 

    $user = User::find_by_clef_id($signed_payload["clef_id"]);
    \Clef\Clef::verify_login_payload($payload_bundle, $user->public_key);

`verify_login_payload` validates the payload, verifies that it originated from your website by verifying with your website's public key, and verifies that the user signed it. If it fails, it will throw an exception of the type `\Clef\VerificationError` with a message indicating the error. 

If verification succeeds, you can log the user in as you normally would. 
Sample App
----------

If you'd like to see an example of this library in action, check out the Clef PHP sample application [here](https://github.com/clef/sample-php).
 
Resources
--------
Check out the [API docs](http://docs.getclef.com/v1.0/docs/).     
Access your [developer dashboard](https://getclef.com/user/login).
