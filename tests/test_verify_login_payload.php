
<?php

class VerifyLoginPayloadTest extends PHPUnit_Framework_TestCase {

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
            ->setMethods(array("verify"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("verify")
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

        $this->assertTrue($client->verify_login_payload($payload, $this->user_public_key));
    }

    /**
     * @expectedException        \Clef\InvalidPayloadHashError
     * @expectedExceptionMessage payload_hash does not match payload_json
    */
    public function testInvalidPayloadHash() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(null)
            ->getMock();

        $payload_json = json_encode(array("a" => 1));
        $payload_hash = "badhash";
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

        $client->verify_login_payload($payload, $this->user_public_key);
    }

    /**
     * @expectedException        \Clef\BadSignatureError
     * @expectedExceptionMessage Invalid signature for application
    */
    public function testInvalidApplicationSignature() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(null)
            ->getMock();

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

        $client->verify_login_payload($payload, $this->user_public_key);
    }

    /**
     * @expectedException        \Clef\BadSignatureError
     * @expectedExceptionMessage Invalid signature for user
    */
    public function testInvalidUserSignature() {
        $good_signature = "goodsignature";
        $bad_signature = "badsignature";
        $payload_json = json_encode(array("a" => 1));
        
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("verify"))
            ->getMock();

        $client
            ->expects($this->exactly(2))
            ->method("verify")
            ->withConsecutive(
                array($payload_json, $good_signature, $this->configuration->getPublicKey()),
                array($payload_json, $bad_signature, $this->user_public_key)
            )
            ->will($this->returnCallback(function($data, $signature, $publickey) {
                if ($signature === "goodsignature") {
                    return true;
                }  else {
                    return false;
                }
            }));

        $payload_hash = $client->hash($payload_json);
        $payload = array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash,
            "signatures" => array(
                "application" => array(
                    "signature" => $good_signature,
                    "type" => "rsa-sha256"
                ),
                "user" => array(
                    "signature" => $bad_signature,
                    "type" => "rsa-sha256"
                )
            )
        );

        $client->verify_login_payload($payload, $this->user_public_key);
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage No signatures provided
    */
    public function testInvalidMissingSignatures() {
        
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(null)
            ->getMock();

        $payload_json = json_encode(array("a" => 1));
        $payload_hash = $client->hash($payload_json);
        $payload = array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash
        );

        $client->verify_login_payload($payload, $this->user_public_key);
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage No application signature
    */
    public function testInvalidMissingApplicationSignature() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(null)
            ->getMock();

        $payload_json = json_encode(array("a" => 1));
        $payload_hash = $client->hash($payload_json);
        $payload = array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash,
            "signatures" => array(
                "user" => array()
            )
        );

        $client->verify_login_payload($payload, $this->user_public_key);
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage No user signature provided
    */
    public function testInvalidMissingUserSignature() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(null)
            ->getMock();

        $payload_json = json_encode(array("a" => 1));
        $payload_hash = $client->hash($payload_json);
        $payload = array(
            "payload_json" => $payload_json,
            "payload_hash" => $payload_hash,
            "signatures" => array(
                "application" => array(
                    "signature" => ""
                )
            )
        );

        $client->verify_login_payload($payload, $this->user_public_key);
    }
}
