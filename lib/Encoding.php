<?php

namespace Clef;

trait Encoding {
    public function base64url_encode($data) {
        return strtr(base64_encode($data), '+/=', '-_,');
    }

    public function base64url_decode($data) {
        return base64_decode(strtr($data, '-_=', '+/,'));
    }
}
