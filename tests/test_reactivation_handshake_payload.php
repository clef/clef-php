<?php

class TestReactivationHandshakePayload extends PHPUnit_Framework_TestCase
{
    protected function setUp() {
        $this->keypair = openssl_pkey_new(
            array(
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA
            )
          );
        $this->public_key = openssl_get_publickey(openssl_pkey_get_details($this->keypair)['key']);
        $this->configuration = new \Clef\Configuration(
            array(
            "id" => "id",
            "secret" => "secret",
            "keypair" => $this->keypair,
            "confirmation_public_key" => $this->public_key,
            "initiation_public_key" => $this->public_key
          )
        );
    }

    public function testSignReactivationPayload() {
        $client = $this->getMockBuilder('\Clef\Client')
            ->setConstructorArgs([$this->configuration])
            ->setMethods(['assert_keys_in_payload', 'sign_payload'])
            ->getMock();

        $sample_payload = array(
            "type" => "reactivation_handshake",
            "reactivation_token" => "test"
        );

        $client->expects($this->once())
            ->method('sign_payload')
            ->with($sample_payload);

        $client->expects($this->once())
            ->method('assert_keys_in_payload')
            ->with($sample_payload, array("reactivation_token"));

        $client->sign_reactivation_payload($sample_payload);
    }

  public function testSendProperPayload() {
    $token = '12345';
    $client = $this->getMockBuilder("\Clef\Client")
      ->setConstructorArgs([$this->configuration])
      ->setMethods(['get', 'verify_reactivation_payload', 'encode_payload'])
      ->getMock();

    $client->expects($this->once())
      ->method('encode_payload')
      ->willReturn('encoded');

    $client->expects($this->once())
      ->method('get')
      ->with(
        "reactivations/$token",
        array(),
        array(
          'Authorization' => 'Payload encoded'
        )
      );

    $client->get_reactivation_payload($token);
  }

  public function testExpectCorrectResponse() {
    $token = '54321';
    $message = '{"application_id":"ffdafb0796c072a22ef7aa6ef324cec2","clef_id":4283383571,"nonce":"57736bf78ac8f3e81173225b","public_keys":{"current":{"bundle":"-----BEGIN PUBLIC KEY-----\nMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA8BwwnqEA1R4JER2MObK4\n6m0Eoq6hl\/JbbtaKSi37eKkTWz55QPz6PQ+m1jeBKEznTsj0vrbvuoZ6o05LR8N5\nLgFsz2ss4GNS8Me7et0O1nyQi91azHPdhOyaKx1KJhUk+L4Jgd+FN38PQF2XRy9X\nj0zc4WGVum7A4mZoj19eqTiP3WOwQL+\/FutlypNsp6Qdj5o8gzMS3Vdp7PWhA4ml\nSCLCAZ48zqpffAJihj1tSziA9X2O0e7mm59r8qXNJ6cmEzHGcK2bYi68J+Zbd\/6Q\nqUUzQ+5H\/2zzDWVxVWROHRL2pqZv80Ysil8ZZA1fxGnYqupeJQ\/d6bGSEOLmwT3k\nYwIBIw==\n-----END PUBLIC KEY-----","fingerprint":"2c146010c5c2da25d4367d18be464ddc65d8bed9","type":"rsa"},"previous":{"bundle":"-----BEGIN PUBLIC KEY-----\nMIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEA8BwwnqEA1R4JER2MObK4\n6m0Eoq6hl\/JbbtaKSi37eKkTWz55QPz6PQ+m1jeBKEznTsj0vrbvuoZ6o05LR8N5\nLgFsz2ss4GNS8Me7et0O1nyQi91azHPdhOyaKx1KJhUk+L4Jgd+FN38PQF2XRy9X\nj0zc4WGVum7A4mZoj19eqTiP3WOwQL+\/FutlypNsp6Qdj5o8gzMS3Vdp7PWhA4ml\nSCLCAZ48zqpffAJihj1tSziA9X2O0e7mm59r8qXNJ6cmEzHGcK2bYi68J+Zbd\/6Q\nqUUzQ+5H\/2zzDWVxVWROHRL2pqZv80Ysil8ZZA1fxGnYqupeJQ\/d6bGSEOLmwT3k\nYwIBIw==\n-----END PUBLIC KEY-----","fingerprint":"2c146010c5c2da25d4367d18be464ddc65d8bed9","type":"rsa"}},"test":true,"timestamp":1457571964,"type":"reactivation"}';
    $client = $this->getMockBuilder("\Clef\Client")
      ->setConstructorArgs([$this->configuration])
      ->setMethods(['get', 'encode_payload', 'verify_reactivation_payload'])
      ->getMock();

    $client->expects($this->once())
      ->method('encode_payload')
      ->willReturn('encoded');

    $client->expects($this->once())
      ->method('get')
      ->willReturn([
        'payload_json' => $message,
      ]);

    $payload = $client->get_reactivation_payload($token);
    $this->assertArrayHasKey('public_keys', $payload);
    $this->assertArrayHasKey('type', $payload);
    $this->assertArrayHasKey('application_id', $payload);
    $this->assertArrayHasKey('timestamp', $payload);
    $this->assertArrayHasKey('clef_id', $payload);
  }

  public function testVerifyReactivationPayloadSignatures () {
    $sample_contained_payload = json_encode(array("major" => "key"));
    $client = new \Clef\Client($this->configuration);
    $sample_payload = array(
      "payload_json" => $sample_contained_payload,
      "payload_hash" => $client->hash($sample_contained_payload),
      "signatures" => array(
        "confirmation" => array(
          "signature" => $client->strict_base64_encode($client->sign($sample_contained_payload, $this->keypair)),
          "type" => "rsa-256"
        ),
        "initiation" => array(
          "signature" => $client->strict_base64_encode($client->sign($sample_contained_payload, $this->keypair)),
          "type" => "rsa-256"
        ),
      )
    );

    $client->verify_reactivation_payload($sample_payload);
  }

  public function testVerifyReactivationOnlyCheckInitiationSignature () {
    $sample_contained_payload = json_encode(array("major" => "key"));
    $client = $this->getMockBuilder("\Clef\Client")
      ->setConstructorArgs([$this->configuration])
      ->setMethods(['assert_test_payload'])
      ->getMock();

    $sample_payload = array(
      "payload_json" => $sample_contained_payload,
      "payload_hash" => $client->hash($sample_contained_payload),
      "signatures" => array(
        "confirmation" => array(
          "signature" => $client->strict_base64_encode($client->sign($sample_contained_payload, $this->keypair)),
          "type" => "rsa-256"
        ),
        "initiation" => array(
          "signature" => $client->strict_base64_encode($client->sign($sample_contained_payload, $this->keypair)),
          "type" => "rsa-256"
        ),
      )
    );

    $client->expects($this->once())
        ->method('assert_test_payload')
        ->with($sample_payload);

    $client->verify_reactivation_payload($sample_payload, array('unsafe_do_not_verify_confirmation_signature' => 1));
  }

  public function testVerifyReactivationForceCheckOfConfirmationSignature () {
    $sample_contained_payload = json_encode(array("major" => "key"));
    $client = $this->getMockBuilder("\Clef\Client")
      ->setConstructorArgs([$this->configuration])
      ->setMethods(['assert_test_payload'])
      ->getMock();

    $sample_payload = array(
      "payload_json" => $sample_contained_payload,
      "payload_hash" => $client->hash($sample_contained_payload),
      "signatures" => array(
        "confirmation" => array(
          "signature" => $client->strict_base64_encode($client->sign($sample_contained_payload, $this->keypair)),
          "type" => "rsa-256"
        ),
        "initiation" => array(
          "signature" => $client->strict_base64_encode($client->sign($sample_contained_payload, $this->keypair)),
          "type" => "rsa-256"
        ),
      )
    );

    $client->expects($this->exactly(0))
        ->method('assert_test_payload');

    $client->verify_reactivation_payload($sample_payload, array('unsafe_do_not_verify_confirmation_signature' => 0));
    $client->verify_reactivation_payload($sample_payload);
  }

}
