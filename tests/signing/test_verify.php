<?php

class VerifyTest extends PHPUnit_Framework_TestCase {

    protected function setUp() {
        $this->configuration = new \Clef\Configuration(array(
            "id" => "id",
            "secret" => "secret",
            "keypair" => openssl_pkey_new(array(
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ))
        ));

        $this->user_private_key = openssl_pkey_new(array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA
        ));
        $this->user_public_key =  openssl_get_publickey(openssl_pkey_get_details($this->user_private_key)['key']);
    }

    public function testVerifyValid() {
        $client = new \Clef\Client($this->configuration);
        $data = "thisisdata";
        $signature = $client->sign($data, $this->user_private_key);
        $this->assertTrue($client->verify($data, $signature, $this->user_public_key));
    }

    public function testVerifyInvalid() {
        $client = new \Clef\Client($this->configuration);
        $data = "thisisdata";
        $signature = $client->sign($data, $this->user_private_key);
        $this->assertFalse($client->verify($data, $signature . "bad", $this->user_public_key));
    }
}
