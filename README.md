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

#### Logging in a user

When a user logs in with Clef, the browser will redirect to your `data-redirect-url`. To retrieve user information, call `get_login_information` in that endpoint: 

    \Clef\Clef::initialize(APP_ID, APP_SECRET);
    $response = \Clef\Clef::get_login_information($_GET["code"]);

For what to do after getting user information, check out our documentation on
[Associating users](http://docs.getclef.com/v1.0/docs/persisting-users).

#### Logging out a user

When you configure your Clef integration, you can also set up a logout hook URL. Clef sends a POST to this URL whenever a user logs out with Clef, so you can log them out on your website too.

    \Clef\Clef::initialize(APP_ID, APP_SECRET);
    $clef_id = \Clef\Clef::get_logout_information($_POST["logout_token"]);

For what to do after getting a user who's logging out's `clef_id`, see our
documentation on [Database
logout](http://docs.getclef.com/v1.0/docs/database-logout).


Sample App
----------

If you'd like to see an example of this library in action, check out the Clef PHP sample application [here](https://github.com/clef/sample-php).
 
Resources
--------
Check out the [API docs](http://docs.getclef.com/v1.0/docs/).     
Access your [developer dashboard](https://getclef.com/user/login).
