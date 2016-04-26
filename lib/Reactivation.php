<?php

namespace Clef;

trait Reactivation {
    public function sign_reactivation_payload($payload) {
        $payload["type"] = "reactivation_handshake";
        return $this->sign_action_payload($payload, array("reactivation_token"));
    }

    public function verify_reactivation_payload($payload, $options = array()) {
      $this->assert_payload_hash_valid($payload);
      $this->assert_signatures_present($payload, array("initiation"));
      $this->assert_signature_valid($payload, "initiation", $this->configuration->initiation_public_key);

      $is_test_reactivation = isset($options['unsafe_do_not_verify_confirmation_signature']) &&
          $options['unsafe_do_not_verify_confirmation_signature'] == 1;

      if ($is_test_reactivation){
        $this->assert_test_payload($payload);
      } else {
        $this->assert_signatures_present($payload, array("confirmation"));
        $this->assert_signature_valid($payload, "confirmation", $this->configuration->confirmation_public_key);
      }

      return true;
    }
}
