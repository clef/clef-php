<?php

namespace Clef;

trait Requests {

    private function doApiRequest($path, $options=array(method => 'POST')) {
        switch ($options['method']) {
            case "POST":
                $requestOptions = array('http' =>
                    array(
                        'method'  => 'POST',
                        'header'  => 'Content-type: application/x-www-form-urlencoded',
                        'ignore_errors' => true
                    )
                );

                if (isset($options['data'])) {
                    $requestOptions['http']['content'] = http_build_query($options['data']);
                }

                break;
            case "GET":
                $requestOptions = array('http' =>
                    array(
                        'method'  => 'GET',
                        'ignore_errors' => true
                    )
                );

                if (isset($options['data'])) {
                    $path .= '?' . http_build_query($options['data']);
                }

                break;
            default:
                throw new Exception("Invalid Clef API request method.");
        }

        $url = $this->configuration->api_base . '/' . $this->configuration->api_version . $path;
        $response = @file_get_contents($url, false, stream_context_create($requestOptions));

        if ($response !== false) {
            try {
                return json_decode($response);
            } catch (Exception $e) {
                throw new ServerError("An error occurred while processing your Clef API request: " . $response);
            }
        } else {
            throw new ConnectionError("An error occurred while trying to connect to the Clef API. Please check your connection and try again.");
        }
    }

}
