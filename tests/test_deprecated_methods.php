<?php

class DeprecatedMethodsTest extends PHPUnit_Framework_TestCase {

    public function testGetApiID() {
        \Clef\Clef::initialize("id", "secret");
        $this->assertEquals(\Clef\Clef::getApiID(), "id");
    }

    public function testGetApiSecret() {
        \Clef\Clef::initialize("id", "secret");
        $this->assertEquals(\Clef\Clef::getApiSecret(), "secret");
    }

    public function getSetGetApiVersion() {
        \Clef\Clef::initialize("id", "secret");
        $this->assertEquals(\Clef\Clef::getApiVersion(), "v1");

        \Clef\Clef::setApiVersion("v2");

        $this->assertEquals(\Clef\Clef::getApiVersion(), "v2");
    }
}
