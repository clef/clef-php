<?php

class SignCustomPayloadTest extends PHPUnit_Framework_TestCase {

    protected function setUp() {
        $this->configuration = new \Clef\Configuration(array(
            "id" => "id",
            "secret" => "secret",
            "keypair" => openssl_pkey_new(array(
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ))
        ));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing clef_id in payload.
    */
    public function testMissingClefID() {
        \Clef\Clef::configure($this->configuration);
        \Clef\Clef::sign_login_payload(array());
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing nonce in payload.
    */
    public function testMissingNonce() {
        \Clef\Clef::configure($this->configuration);
        \Clef\Clef::sign_custom_payload(array('clef_id' => '1234'));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing redirect_url in payload.
    */
    public function testMissingRedirectURL() {
        \Clef\Clef::configure($this->configuration);
        \Clef\Clef::sign_custom_payload(array('clef_id' => '1234', 'nonce' => 'nonce'));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing session_id in payload.
    */
    public function testMissingSessionID() {
        \Clef\Clef::configure($this->configuration);
        \Clef\Clef::sign_custom_payload(array('clef_id' => '1234', 'nonce' => 'nonce', 'redirect_url' => 'http://test.com'));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing type in payload.
    */
    public function testMissingType() {
        \Clef\Clef::configure($this->configuration);
        \Clef\Clef::sign_custom_payload(array('clef_id' => '1234', 'nonce' => 'nonce', 'redirect_url' => 'http://test.com', 'session_id' => '123'));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing description in payload.
    */
    public function testMissingDescription() {
        \Clef\Clef::configure($this->configuration);
        \Clef\Clef::sign_custom_payload(array('clef_id' => '1234', 'nonce' => 'nonce', 'redirect_url' => 'http://test.com', 'session_id' => '123', 'type' => 'custom_type'));
    }

}
