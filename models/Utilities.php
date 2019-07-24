<?php
/**
 * Created by PhpStorm.
 * User: keshtgar
 * Date: 6/19/19
 * Time: 11:20 AM
 */

class Utilities
{

    public function dataForSignature($headers) {
        $data = '';
        if ($headers == "host" || $headers == "Host") {
            $data = "host: accounts.pod.land";
        }
        elseif ($headers == "host date" || $headers == "Host Date")  {
            $data = "host: accounts.pod.land". PHP_EOL ." date: Mon 17 2019 18:14:25 GMT+0430";
//            $data = "host: accounts.pod.land\n date: Mon Jun 17 2019 18:13:25 GMT+0430";
        }
        return $data;
    }

    public function createSign($data, $privateKey){
//        if (openssl_sign($data,$signature , $params['privateKey'], $params['algorithm'])) {
        if (openssl_sign($data,$signature , $privateKey, OPENSSL_ALGO_SHA256)) {
            $signature = base64_encode($signature);
            return $signature;
        }
    }

}