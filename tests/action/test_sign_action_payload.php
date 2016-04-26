<?php

class SignActionPayloadTest extends PHPUnit_Framework_TestCase {

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

    public function testReturnsSignedPayload() {
        $signed_payload = array("signed" => "payload");

        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("sign_payload"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("sign_payload")
            ->will($this->returnValue($signed_payload));

       $payload = $client->sign_action_payload(array("key" => 1), array("key"));

       $this->assertEquals($payload, $signed_payload);
    }

    /**
     * @expectedException        \Clef\InvalidPayloadError
     * @expectedExceptionMessage Missing key in payload.
    */
    public function testMissingKeyRaisesError() {
       $client = new \Clef\Client(new \Clef\Configuration(array()));
       $client->sign_action_payload(array(), array("key"));
    }
}
