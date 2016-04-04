<?php

namespace Clef;

trait Requests {
    public function post($path, $data = array(), $headers = array()) {
        return $this->send_request(\Requests::POST, $path, $data, $headers);
    }

    public function get($path, $data = array(), $headers = array()) {
        return $this->send_request(\Requests::GET, $path, $data, $headers);
    }

    private function send_request($type, $path, $data = array(), $headers = array()) {
        $full_uri = "{$this->configuration->api_base}/{$this->configuration->api_version}/{$path}";
        try {
          $response = \Requests::request($full_uri, $headers, $data, $type);
          if ($response->status_code != 200) {
            throw new ServerError("The Clef API raised an error: $response->body.");
          } else {
            return json_decode($response->body, true);
          }
        } catch (Exception $e) {
            throw new ServerError("An error occurred while processing your Clef API request: " . $response);
        }
    }
}
