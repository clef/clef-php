<?php

namespace Clef;

trait Action {
    public function sign_action_payload($payload, $required_keys=array()) {
        $this->assert_keys_in_payload($payload, $required_keys);
        return $this->sign_payload($payload);
    }

    public function verify_action_payload($payload, $user_public_key) {
        $this->assert_payload_hash_valid($payload);
        $this->assert_signatures_present($payload, array("application", "user"));
        $this->assert_signature_valid($payload, "application", $this->configuration->getPublicKey());
        $this->assert_signature_valid($payload, "user", $user_public_key);

        return true;
    }
}
