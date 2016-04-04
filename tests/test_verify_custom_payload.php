<?php

class VerifyCustomPayloadTest extends PHPUnit_Framework_TestCase {

    protected function setUp() {
        $this->configuration = new \Clef\Configuration(array(
            "id" => "id",
            "secret" => "secret",
            "keypair" => openssl_pkey_new(array(
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            ))
        ));

        $this->user_public_key = openssl_pkey_new(array(
            "private_key_bits" => 2048,
            "private_key_type" => OPENSSL_KEYTYPE_RSA
        ));
    }

    public function testVerifyValidPayload() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("verify_action_payload"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("verify_action_payload")
            ->will($this->returnValue(true));

        $payload_json = json_encode(array("a" => 1));
        $payload_hash = $client->hash($payload_json);
        $payload = array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash,
            "signatures" => array(
                "application" => array(
                    "signature" => $client->base64url_encode("goodsignature"),
                    "type" => "rsa-sha256"
                ),
                "user" => array(
                    "signature" => $client->base64url_encode("goodsignature"),
                    "type" => "rsa-sha256"
                )
            )
        );

        $this->assertTrue($client->verify_custom_payload($payload, $this->user_public_key));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadHashError
    */
    public function testInvalidPayloadHash() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("verify_action_payload"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("verify_action_payload")
            ->will($this->throwException(new \Clef\InvalidPayloadHashError));

        $payload_json = json_encode(array("a" => 1));
        $payload_hash = $client->hash($payload_json);
        $payload = array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash,
            "signatures" => array(
                "application" => array(
                    "signature" => $client->base64url_encode("badsignature"),
                    "type" => "rsa-sha256"
                ),
                "user" => array(
                    "signature" => $client->base64url_encode("goodsignature"),
                    "type" => "rsa-sha256"
                )
            )
        );

        $client->verify_custom_payload($payload, $this->user_public_key);
    }

    /**
     * @expectedException        \Clef\BadSignatureError
    */
    public function testInvalidSignature() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("verify_action_payload"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("verify_action_payload")
            ->will($this->throwException(new \Clef\BadSignatureError));

        $payload_json = json_encode(array("a" => 1));
        $payload_hash = $client->hash($payload_json);
        $payload = array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash,
            "signatures" => array(
                "application" => array(
                    "signature" => $client->base64url_encode("badsignature"),
                    "type" => "rsa-sha256"
                ),
                "user" => array(
                    "signature" => $client->base64url_encode("goodsignature"),
                    "type" => "rsa-sha256"
                )
            )
        );

        $client->verify_action_payload($payload, $this->user_public_key);
    }
}
