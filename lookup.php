<?php

// Get IP information from API
function getInfo($ip = null)
{
    if (is_null($ip)) {
        $ip = ipAddress();
    }
    $ch = curl_init('https://whois.configserver.pro/api/v1/lookup/ip?ip=' . $ip);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'apiKey: TOKEN'
    ));
    curl_setopt_array($ch, [
        CURLOPT_SSL_VERIFYPEER => false,
        CURLOPT_SSL_VERIFYHOST => false,
        CURLOPT_RETURNTRANSFER => true,
    ]);
    $response = curl_exec($ch);
    curl_close($ch);

    return $response;
}

// Get real IP from $SERVER parameter 

function ipAddress()
{

    $ip_keys = [
        'HTTP_X_SUCURI_CLIENTIP',
        'HTTP_CLIENT_IP',
        'HTTP_X_FORWARDED_FOR',
        'HTTP_X_FORWARDED',
        'HTTP_X_CLUSTER_CLIENT_IP',
        'HTTP_FORWARDED_FOR',
        'HTTP_FORWARDED',
        'REMOTE_ADDR',
    ];
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === TRUE) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                // trim for safety measures
                $ip = trim($ip);
                // attempt to validate IP
                if (filter_var(
                    $ip,
                    FILTER_VALIDATE_IP,
                    FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
                ) === FALSE) {
                    continue;
                }
                return $ip;
            }
        }
    }
    $ip = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : FALSE;
    return $ipAddress = $ip;
}

$ipAddr = ipAddress();
$lookupIP = getInfo($ipAddr);
