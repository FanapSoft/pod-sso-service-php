<?php
namespace Pod\Sso\Service;
require __DIR__ . '/../vendor/autoload.php';

use Pod\Base\Service\BaseService;
use Pod\Base\Service\ApiRequestHandler;
use Exception;
use Pod\Base\Service\ClientInfo;
use Pod\Base\Service\Exception\InvalidConfigException;
use Pod\Base\Service\Exception\PodException;
use Pod\Base\Service\Exception\RequestException;


class SSOService extends BaseService {

    private $baseUri;
    /**
     * @var ClientInfo
     */
    private $clientInfo;
    private $header;
    private static $ssoApi =
    [
        // #1, get oauth access token
        'getAccessToken' => [
            'subUri' => 'oauth2/token',
            'method' => 'POST'
        ],

        // #1, refresh oauth access token
        'refreshAccessToken' => [
            'subUri' => 'oauth2/token',
            'method' => 'POST'
        ],

        // #2, get oauth token info
        'getTokenInfo' => [
            'subUri' => 'oauth2/token/info',
            'method' => 'POST'
        ],

        // #3, revoke token
        'revokeToken' => [
            'subUri' => 'oauth2/token/revoke',
            'method' => 'POST'
        ],

        // #4, Handshake
        'handshake' => [
            'subUri' => 'oauth2/clients/handshake',
            'method' => 'POST'
        ],

        // #5 get Grant Code
        'signatureAuthorize' => [
            'subUri' => 'oauth2/otp/authorize',
            'method' => 'POST'
        ],

        // #6 verify One Time Token
        'verifyOTP' => [
            'subUri' => 'oauth2/otp/verify',
            'method' => 'POST'
        ],

        // #7, get oauth access token by OTP
        'getAccessTokenByOTP' => [
            'subUri' => 'oauth2/token',
            'method' => 'POST'
        ],

    ];

    public function __construct($clientInfo = null)
    {
        parent::__construct();
        $this->clientInfo = $clientInfo;
        $this->baseUri = self::$config['Production']['SSO-ADDRESS'];
        self::$jsonSchema = json_decode(file_get_contents(__DIR__. '/../jsonSchema.json'), true);
        $this->header = [
            'Content-Type' => 'application/x-www-form-urlencoded'
        ];
    }

    /**
     * get login url
     *
     * @param array $params
     *
     * @return string
     * @throws InvalidConfigException
     */
    public function getLoginUrl($params = [])
    {
        $params['client_id'] = isset($params['client_id']) ? $params['client_id'] : $this->clientInfo->getClientId();

        if (isset($params['scope'])) {
            $params['scope'] = is_array($params['scope']) ? implode('+', $params['scope']) : $params['scope'];
        } else {
            $params['scope'] = "profile";
        }

        if (!isset($params['response_type'])) {
            $params['response_type'] = 'code';
        }

        if (!isset($params['redirect_uri'])) {
            $params['redirect_uri'] = $this->clientInfo->getRedirectUri();
        }

        return rtrim($this->baseUri, '/').'/oauth2/authorize/?'.str_replace('%2B', '+', http_build_query($params)).PHP_EOL;
    }

    // get Access Token
    /**
     * @param array $params
     *      @option string 'grant_type'     [authorization_code, refresh_token, password]
     *      @option string 'code'
     *      @option string 'redirect_uri'
     *      @option string 'callback_uri'
     *      @option string 'client_id'
     *      @option string 'client_secret'
     * @throws RequestException
     * @throws PodException
     * @return mixed
     * @return mixed
     *
     */
    public function getAccessToken ($params) {
        $apiName = 'getAccessToken';

        // set client id and client secret and redirect uri
        $params['client_id'] = isset($params['client_id']) ? $params['client_id'] : $this->clientInfo->getClientId();
        $params['client_secret'] = isset($params['client_secret']) ? $params['client_secret'] : $this->clientInfo->getClientSecret();
        $params['redirect_uri'] = isset($params['redirect_uri']) ? $params['redirect_uri'] : $this->clientInfo->getRedirectUri();
        $params['grant_type'] = 'authorization_code';

        array_walk_recursive($params, 'self::prepareData');

        // if method changes this line handle it
        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        $option = [
            'headers' => $this->header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
        return ApiRequestHandler::Request(
            $this->baseUri,
            self::$ssoApi[$apiName]['method'],
            self::$ssoApi[$apiName]['subUri'],
            $option,
            true
        );
    }

    // refresh Token
    /**
     * @param array $params
     *      @option string 'grant_type'   [authorization_code, refresh_token, password]
     *      @option string 'redirect_uri'
     *      @option string 'client_id'
     *      @option string 'client_secret'
     *      @option string 'refresh_token'  [refresh_token is used for refreshing access token fill this one instead of code]
     * @throws RequestException
     * @throws PodException
     * @return mixed
     * @return mixed
     *
     */
    public function refreshAccessToken ($params) {
        $apiName = 'refreshAccessToken';

        // set client id and client secret and redirect uri
        $params['client_id'] = isset($params['client_id']) ? $params['client_id'] : $this->clientInfo->getClientId();
        $params['client_secret'] = isset($params['client_secret']) ? $params['client_secret'] : $this->clientInfo->getClientSecret();
        $params['redirect_uri'] = isset($params['redirect_uri']) ? $params['redirect_uri'] : $this->clientInfo->getRedirectUri();
        $params['grant_type'] = 'refresh_token';

        array_walk_recursive($params, 'self::prepareData');


        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        $option = [
            'headers' => $this->header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
        return ApiRequestHandler::Request(
            $this->baseUri,
            self::$ssoApi[$apiName]['method'],
            self::$ssoApi[$apiName]['subUri'],
            $option,
            true
        );
    }

    // get Token Info
    /**'
     * @param array $params
     *      @option string 'token_type_hint'   ['access_token' | 'refresh_token' | 'id_token']
     *      @option string 'client_id'
     *      @option string 'client_secret'
     *      @option string 'token'  [access_token | refresh_token | id_token]
     * @throws RequestException
     * @throws PodException
     * @return mixed
     * @return mixed
     */
    public function getTokenInfo ($params) {
        $apiName = 'getTokenInfo';

        // set client id and client secret
        $params['client_id'] = isset($params['client_id']) ? $params['client_id'] : $this->clientInfo->getClientId();
        $params['client_secret'] = isset($params['client_secret']) ? $params['client_secret'] : $this->clientInfo->getClientSecret();
        array_walk_recursive($params, 'self::prepareData');

        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        $option = [
            'headers' => $this->header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
        return ApiRequestHandler::Request(
            $this->baseUri,
            self::$ssoApi[$apiName]['method'],
            self::$ssoApi[$apiName]['subUri'],
            $option,
            true
        );
    }

    // Revoke Token
    /**
     * @param array  $params
     *      @option string 'token_type_hint'   ['access_token' | 'refresh_token']
     *      @option string 'client_id'
     *      @option string 'client_secret'
     *      @option string 'token'  [access_token | refresh_token ]
     * @throws RequestException
     * @throws PodException
     * @return mixed
     */
    public function revokeToken ($params) {
        $apiName = 'revokeToken';

        // set client id and client secret
        $params['client_id'] = isset($params['client_id']) ? $params['client_id'] : $this->clientInfo->getClientId();
        $params['client_secret'] = isset($params['client_secret']) ? $params['client_secret'] : $this->clientInfo->getClientSecret();
        array_walk_recursive($params, 'self::prepareData');

        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        $option = [
            'headers' => $this->header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
            return ApiRequestHandler::Request(
                $this->baseUri,
                self::$ssoApi[$apiName]['method'],
                self::$ssoApi[$apiName]['subUri'],
                $option,
                true
            );
    }

    // Handshake
    /**
     * @param array $params
     *      @option string 'api_token'
     *      @option string 'device_name'
     *      @option string 'device_uid'   ['access_token' | 'refresh_token']
     *      @option double 'device_lat'
     *      @option double 'device_lon'
     *      @option string 'device_os_version'
     *      @option string 'device_type'
     *      @option string 'algorithm'
     * @throws RequestException
     * @throws PodException
     * @return mixed
     * @return mixed
     */
    public function handshake($params) {
        $apiName = 'handshake';
        $header = $this->header;
        $header['Authorization'] = 'Bearer '. $params['api_token'];


        // set client id
        $params['client_id'] = isset($params['client_id']) ? $params['client_id'] : $this->clientInfo->getClientId();
        array_walk_recursive($params, 'self::prepareData');

        $relativeUri = self::$ssoApi[$apiName]['subUri'] .  '/' . $params['client_id'];

        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        $option = [
            'headers' => $header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
        unset($params['api_token']);
        return ApiRequestHandler::Request(
            $this->baseUri,
            self::$ssoApi[$apiName]['method'],
            $relativeUri,
            $option,
            true
        );
    }

    // get OTP (One Time Token)
    /**
     * @param array $params
     *      @option string 'headerType'
     *      @option string 'privateKey'
     *      @option string 'keyId'
     *      @option string 'identity'
     *      @option string 'response_type'
     *      @option string 'identityType'
     *      @option string 'loginAsUserId'
     *      @option string 'state'
     *      @option string 'client_id'
     *      @option string 'redirect_uri'
     *      @option string 'callback_uri'
     *      @option string 'scope'
     *      @option string 'code_challenge'
     *      @option string 'code_challenge_method'
     *      @option string 'referrer'
     *      @option string 'referrerType' [id | username | phone_number | email | nationalCode]
     * @throws RequestException
     * @throws PodException
     * @return mixed
     * @return mixed
     */
    public function signatureAuthorize($params) {

        array_walk_recursive($params, 'self::prepareData');
        $data = '';
        $authorizationHeader = '';
        
        $headerType = isset($params['headerType']) ? $params['headerType'] : 'host';
        unset($params['headerType']);

//        if ($headerType == 'host' || $headerType == 'Host') {
            $data = 'host: accounts.pod.land';
//        }
//        elseif ($headerType == 'host date' || $headerType == 'Host Date')  {
//            $data = 'host: accounts.pod.land'. PHP_EOL .' date: Mon 17 2019 18:14:25 GMT+0430';
//            $data = 'host: accounts.pod.land\n date: Mon Jun 17 2019 18:13:25 GMT+0430';
//
//        }

//        if (openssl_sign($data,$signature , $params['privateKey'], $params['algorithm'])) {
        if (openssl_sign($data,$signature , $params['privateKey'], OPENSSL_ALGO_SHA256)) {
            $signature = base64_encode($signature);
            $authorizationHeader = 'Signature keyId=' . $params['keyId'] .
                ',signature=' . $signature . ',headers=' . $headerType;
        }
        $apiName = 'signatureAuthorize';

        $header = $this->header;
        $header['Authorization'] = $authorizationHeader;

        $relativeUri = self::$ssoApi[$apiName]['subUri'] .  '/' . $params['identity'];
        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        $option = [
            'headers' => $header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
        unset($option[$paramKey]['identity']);
        unset($params['headerType']);
        unset($params['privateKey']);
        unset($params['keyId']);
        $result = ApiRequestHandler::Request(
            $this->baseUri,
            self::$ssoApi[$apiName]['method'],
            $relativeUri,
            $option,
            true
        );
        $result['signature'] = $signature;
        return $result;

    }

    // verify OTP
    /**
    * @param array $params
    *      @option string 'headers'   ['host' | 'host date']
    *      @option string 'keyId'
    *      @option string 'signature'
    *      @option string 'identity'
    *      @option string 'otp'
     * @throws RequestException
     * @throws PodException
     * @return mixed
    * @return mixed
    */
    public function verifyOTP($params) {

        $apiName = 'verifyOTP';

        $params['headers'] = isset($params['headers']) ? $params['headers'] : 'host';
        array_walk_recursive($params, 'self::prepareData');
        $relativeUri = self::$ssoApi[$apiName]['subUri'] .  '/' . $params['identity'];
        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        // change header to proper one before send request
        $authorizationHeader = 'Signature keyId=' . $params['keyId'] .
            ',signature=' . $params['signature'] . ',headers=' . $params['headers'];

        $header = $this->header;
        $header['Authorization'] = $authorizationHeader;

        $option = [
            'headers' => $header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
        unset($params['identity']);
        unset($params['keyId']);
        unset($params['signature']);
        unset($params['headers']);

        return ApiRequestHandler::Request(
            $this->baseUri,
            self::$ssoApi[$apiName]['method'],
            $relativeUri,
            $option,
            true
        );
    }

    /**
     * @param array $params
     *      @option string 'grant_type'   [authorization_code, refresh_token, password]
     *      @option string 'code'
     *      @option string 'callback_uri'
     *      @option string 'client_id'
     *      @option string 'client_secret'
     * @throws RequestException
     * @throws PodException
     * @return mixed
     * @return mixed
     *
     */
    public function getAccessTokenByOTP ($params) {
        $apiName = 'getAccessTokenByOTP';

        // set client id and client secret
        $params['grant_type'] = 'authorization_code';
        $params['client_id'] = isset($params['client_id']) ? $params['client_id'] : $this->clientInfo->getClientId();
        $params['client_secret'] = isset($params['client_secret']) ? $params['client_secret'] : $this->clientInfo->getClientSecret();

        array_walk_recursive($params, 'self::prepareData');
        $paramKey = self::$ssoApi[$apiName]['method'] == 'GET' ? 'query' : 'form_params';

        $option = [
            'headers' => $this->header,
            $paramKey => $params,
        ];

        self::validateOption($apiName, $option, $paramKey);
        return ApiRequestHandler::Request(
            $this->baseUri,
            self::$ssoApi[$apiName]['method'],
            self::$ssoApi[$apiName]['subUri'],
            $option,
            true
        );
    }

    public function getOTPScenario($handShakeHeader, $handShakeParams, $signatureAuthorizeHeader, $signatureAuthorizeParams) {

        try {
            $handShakeResult = $this->handshake($handShakeHeader, $handShakeParams);
        }
        catch (Exception $e) {

            print_r([
                'errorCode' => $e->getCode(),
                'message' => $e->getMessage()
            ]);
            return false;
        }

        $signatureAuthorizeHeader['keyId' ] = $handShakeResult['keyId'];

        try {
            $result = $this->signatureAuthorize($signatureAuthorizeHeader, $signatureAuthorizeParams);
        }
        catch (Exception $e) {

            print_r([
                'errorCode' => $e->getCode(),
                'message' => $e->getMessage()
            ]);
            return false;
        }

        return $result;
    }

    public function getAccessTokenByOTPScenario($verifyOTPHeader, $verifyOTPParams, $getAccessTokenByOTPHeader, $getAccessTokenByOTPParams) {

        try {
            $verifyOTPResult = $this->verifyOTP($verifyOTPHeader, $verifyOTPParams);
        }
        catch (Exception $e) {

            print_r([
                'errorCode' => $e->getCode(),
                'message' => $e->getMessage()
            ]);
            return false;
        }

        $getAccessTokenByOTPParams['code' ] = $verifyOTPResult['code'];

        try {
            $result = $this->signatureAuthorize($getAccessTokenByOTPHeader, $getAccessTokenByOTPParams);
        }
        catch (Exception $e) {

            print_r([
                'errorCode' => $e->getCode(),
                'message' => $e->getMessage()
            ]);
            return false;
        }

        return $result;
    }

}