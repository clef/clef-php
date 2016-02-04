<?php

class SignPayloadTest extends PHPUnit_Framework_TestCase {

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

    public function testEncodesPayloadToJSON() {
        $payload_to_sign = array("a" => 1);

        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("add_keys_to_payload"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("add_keys_to_payload")
            ->will($this->returnValue($payload_to_sign));

        $signed_payload = $client->sign_payload($payload_to_sign);
        $this->assertEquals($signed_payload["payload_json"], json_encode($payload_to_sign));
    }

    public function testSignsPayload() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("sign"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("sign")
            ->will($this->returnValue("signature"));

        $payload_to_sign = array("a" => 1);
        $signed_payload = $client->sign_payload($payload_to_sign);

        $decoded_signature = base64_decode($signed_payload["signatures"]["application"]["signature"]);
        $this->assertEquals($decoded_signature, "signature");
    }

    public function testHashesPayload() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("hash"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("hash")
            ->will($this->returnValue("hash"));

        $payload_to_sign = array("a" => 1);
        $signed_payload = $client->sign_payload($payload_to_sign);

        $this->assertEquals($signed_payload["payload_hash"], "hash");
    }

    public function testCreatesAVerifiableSignature() {
        $payload_to_sign = array("a" => 1);

        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("add_keys_to_payload"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("add_keys_to_payload")
            ->will($this->returnValue($payload_to_sign));


        $payload_to_sign = array("a" => 1);
        $signed_payload = $client->sign_payload($payload_to_sign);

        $public_key = openssl_pkey_get_details($this->configuration->getKeypairObject())["key"];

        $this->assertEquals(
            openssl_verify(json_encode($payload_to_sign), base64_decode($signed_payload["signatures"]["application"]["signature"]), openssl_get_publickey($public_key), OPENSSL_ALGO_SHA256), 
            1
        );
    }

    public function testSortsPayload() {
        $payload_to_sign = array("a" => 1, "c" => 2, "b" => 3);

        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(array("add_keys_to_payload"))
            ->getMock();

        $client
            ->expects($this->any())
            ->method("add_keys_to_payload")
            ->will($this->returnValue($payload_to_sign));


        $payload_to_sign = array("a" => 1);
        $signed_payload = $client->sign_payload($payload_to_sign);

        $json_payload = json_decode($signed_payload["payload_json"], true);
        $this->assertEquals(array_keys($json_payload), array("a", "b", "c"));
    }

    public function testAddsDataToPayload() {
        $client = $this->getMockBuilder("\Clef\Client")
            ->setConstructorArgs(array($this->configuration))
            ->setMethods(null)
            ->getMock();

        $payload_to_sign = array("a" => 1);
        $signed_payload = $client->sign_payload($payload_to_sign);

        $json_payload = json_decode($signed_payload["payload_json"], true);
        $this->assertEquals($json_payload["application_id"], $this->configuration->id);
        $this->assertArrayHasKey("timestamp", $json_payload);
    }
}
