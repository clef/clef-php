<?php

class SignLoginPayloadTest extends PHPUnit_Framework_TestCase {

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

    public function testAddsLoginTyoe() {
        $client = new \Clef\Client($this->configuration);
        $payload = $client->sign_login_payload(array('clef_id' => '1234', 'nonce' => 'nonce', 'redirect_url' => 'http://test.com', 'session_id' => '1234'));

        $payload = json_decode($payload['payload_json'], true);
        $this->assertEquals($payload['type'], 'login');
    }
    
    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing clef_id in payload.
    */
    public function testMissingClefID() {
       $client = new \Clef\Client(new \Clef\Configuration(array()));
       $client->sign_login_payload(array());
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing nonce in payload.
    */
    public function testMissingNonce() {
       $client = new \Clef\Client(new \Clef\Configuration(array()));
       $client->sign_login_payload(array('clef_id' => '1234'));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing redirect_url in payload.
    */
    public function testMissingRedirectURL() {
       $client = new \Clef\Client(new \Clef\Configuration(array()));
       $client->sign_login_payload(array('clef_id' => '1234', 'nonce' => 'nonce'));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing session_id in payload.
    */
    public function testMissingSessionID() {
       $client = new \Clef\Client(new \Clef\Configuration(array()));
       $client->sign_login_payload(array('clef_id' => '1234', 'nonce' => 'nonce', 'redirect_url' => 'http://test.com'));
    }
}
