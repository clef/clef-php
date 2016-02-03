<?php

class ConfigurationTest extends PHPUnit_Framework_TestCase {

    public function testSetsCorrectVariables() {
        $configuration = new \Clef\Configuration(array(
            "id" => "id",
            "secret" => "secret"
        ));

        $this->assertEquals($configuration->id, "id");
        $this->assertEquals($configuration->secret, "secret");
    }

    public function testDefaultsAreNotOverridden() {
        $configuration = new \Clef\Configuration(array(
            "id" => "id",
            "secret" => "secret"
        ));

        $this->assertEquals($configuration->api_base, "https://clef.io");
    }

    public function testDefaultsCanBeOverridden() {
        $configuration = new \Clef\Configuration(array(
            "debug" => true,
        ));

        $this->assertEquals($configuration->debug, true);
    }

}
