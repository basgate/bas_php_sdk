<?php

//namespace BasSdk;
include('../BasChecksum.php');
include('../config.php');
// ini_set('memory_limit', '20480M');

/**
 * Bas uses checksum signature to ensure that API requests and responses shared between your 
 * application and Bas over network have not been tampered with. We use SHA256 hashing and 
 * AES128 encryption algorithm to ensure the safety of transaction data.
 *
 * @author     Kamal Hassan
 * @version    0.0.1
 * @link       https://.basgate.com/docs/
 */


class BasSDKService
{
    private static $ContentTypexwww = 'Content-Type: application/x-www-form-urlencoded';
    private static $ContentTypeJson =  array('Content-Type: application/json', 'Accept: text/plain');

    

     // #Region Stage Environment Methods

     static public function getToken($grantType, $code = null)
     {
         $header = array('Content-Type: application/x-www-form-urlencoded');
         $data = array();

        // Check the grant type and set the appropriate data
        if ($grantType === GrantTypes::client_credentials) {
            $data['grant_type'] = GrantTypes::client_credentials;
        } 
        elseif ($grantType === GrantTypes::authorization_code) {
            $data['grant_type'] = GrantTypes::authorization_code;
            $data['code'] = $code;
            $data['redirect_uri'] = self::GetAuthRedirectUrl();
        }
     

         $body = http_build_query($data);
         $response =    self::httpPostGetToken(self::GetTokenUrl(), $body, $header);
         $response = json_decode($response, true);
         return $response;
 
        
     }

      public static function GetUserInfo($code)
     {
         $header = array('Content-Type: application/x-www-form-urlencoded');
         $data = array();
         $data['client_id'] = self::GetClientId();
         $data['client_secret'] = self::GetClientSecret();
         $data['code'] = $code;
         $data['redirect_uri'] = self::GetAuthRedirectUrl();
         $body = http_build_query($data);
 
         if (!is_null($code)) {
             $response =    self::httpPost(self::GetuserInfoUrlV2(), $body, $header, GrantTypes::authorization_code);
             return json_decode($response, true);
         }
         return null;
     }
 
     public static function InitPayment($orderId, $amount, $callBackUrl, $customerInfoId): mixed
     {
         $reqBody = '{"head":{"signature":"sigg","requestTimeStamp":"timess"},"body":bodyy}';
         // $requestTimestamp = gmdate("Y-m-d\TH:i:s\Z");
         $requestTimestamp = (string)  time();
         /* body parameters */
         $params["body"] = array(
             "appId" => self::GetAppId(),
             "requestTimestamp" => $requestTimestamp,
             "orderType" => "PayBill",
             "callBackUrl" => $callBackUrl,
             "customerInfo" => array(
                 "id" => $customerInfoId,
                 "name" => "Test"
             ),
             "amount" => array(
                 "value" => (float) $amount,
                 "currency" => 'YER',
             ),
 
             "orderId" => $orderId,
             "orderDetails" => array(
                 "Id" => $orderId,
                 "Currency" => 'YER',
                 "TotalPrice" => (float) $amount,
             )
         );
         $bodystr = json_encode($params["body"]);
 
         $checksum = BasChecksum::generateSignature($bodystr, self::GetMKey());
 
         if ($checksum === false) {
             error_log(
                 sprintf(
                     /* translators: 1: Event data. */
                     'Could not retrieve signature, please try again Data: %1$s.',
                     $bodystr
                 )
             );
             throw new Exception('Could not retrieve signature, please try again.', self::GetMKey());
         }
 
         /* prepare JSON string for request */
         $reqBody = str_replace('bodyy', $bodystr, $reqBody);
         $reqBody = str_replace('sigg', $checksum, $reqBody);
         $reqBody = str_replace('timess', '1729020006', $reqBody);
         print_r($reqBody);
         echo nl2br("\n") ."";
         $url = self::GetInitiatePaymentUrl();
         $header = array('Accept: text/plain', 'Content-Type: application/json');
         
         //var token
         $response = self::httpPost($url, $reqBody, $header, GrantTypes::client_credentials); 
         //
         if (self::isSandboxEnvironment()) {
             return  json_decode($response, true);
         }
         $isVerify = BasChecksum::verifySignature($bodystr, self::GetMKey(), checksum: $checksum);
         if (!$isVerify) {
             throw new InvalidArgumentException("BasSDKService.verifySignature Invalid_response_signature");
         }
         if (!empty($res['body']['trxToken'])) {
             $data['trxToken'] = $response['body']['trxToken'];
             $data['trxId'] = $response['body']['trxId'];
             $data['callBackUrl'] = $callBackUrl;
         } else {
             error_log(
                 sprintf(
                     /* translators: 1: bodystr, 2:. */
                     'trxToken empty \n bodystr: %1$s , \n $checksum: %2$s.',
                     $bodystr,
                     $checksum
                 )
             );
             $data['trxToken'] = "";
         }
         return  json_decode($response, true);
       
     }
 
 
      public static function CheckPaymentStatus($orderId)
     {
         $requestTimestamp = '1668714632332';
         $header = array('Content-Type: application/json');
 
         $bodyy['RequestTimestamp'] = $requestTimestamp;
         $bodyy['AppId'] = self::GetAppId();
         $bodyy['OrderId'] = $orderId;
 
 
         $bodyyStr = json_encode($bodyy);
 
         $basChecksum = BasChecksum::generateSignature($bodyyStr, self::GetMKey());
 
         $head["Signature"] = $basChecksum;
         $head["RequestTimestamp"] = $requestTimestamp;
 
         $req["Head"] = $head;
         $req["Body"] = $bodyy;
 
         $data = json_encode($req);
         $paymentStatusUrl = self::GetPaymentStatusUrl();
         $resp = self::httpPost(url: $paymentStatusUrl, data: $data, header: $header, grantType: GrantTypes::client_credentials);
 
         return  json_decode($resp, true);
     }
     #endregion


    
    static function httpPost($url, $data, $header, $grantType)
    {
        $tokenResponse = BasSDKService::getToken($grantType);
        if (empty($tokenResponse['access_token'])) {
            throw new Exception("invalid grant"); 
        }

        self::AddOrReplaceKeyToHeader($header, 'Authorization', 'Bearer ' . $tokenResponse['access_token']);
        self::AddOrReplaceKeyToHeader($header, 'User-Agent', 'BasSdk');
        self::AddOrReplaceKeyToHeader($header, 'User-Agent', 'BasSdk');
        self::AddOrReplaceKeyToHeader($header, 'x-client-id', BasSdkService::getClientId());
        self::AddOrReplaceKeyToHeader($header, 'x-app-id', BasSdkService::getAppId());
        self::AddOrReplaceKeyToHeader($header, 'x-sdk-version', ConfigProperties::$CurrentVersion);
        self::AddOrReplaceKeyToHeader($header, 'x-environment', ConfigProperties::$environment);
        self::AddOrReplaceKeyToHeader($header, 'correlationId', BasSdkService::GUID());
        self::AddOrReplaceKeyToHeader($header, 'x-sdk-type', 'php');


        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);

        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);


        if ($httpCode != 200) {
            $msg = "Return httpCode is {$httpCode} \n"
                . curl_error($curl) . "URL: " . $url;
            //echo $msg,nl2br("\n");
            // echo $msg.$errorresponse['Messages'][0];
            curl_close($curl);
            return $msg;
            //return $response;
        } else {
            curl_close($curl);
            return $response;
        }
    }
    static function httpPostGetToken($url, $data, $header)
    {
       
        // self::AddOrReplaceKeyToHeader($header, 'User-Agent', 'BasSdk');
        // self::AddOrReplaceKeyToHeader($header, 'x-client-id', BasSdkService::getClientId());
        // self::AddOrReplaceKeyToHeader($header, 'x-app-id', BasSdkService::getAppId());
        // self::AddOrReplaceKeyToHeader($header, 'x-sdk-version', ConfigProperties::$CurrentVersion);
        // self::AddOrReplaceKeyToHeader($header, 'x-environment', ConfigProperties::$environment);
        // self::AddOrReplaceKeyToHeader($header, 'correlationId', BasSdkService::GUID());
        // self::AddOrReplaceKeyToHeader($header, 'x-sdk-type', 'php');


        $curl = curl_init($url);
        curl_setopt($curl, CURLOPT_POST, true);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);

        $response = curl_exec($curl);
        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);


        if ($httpCode != 200) {
            $msg = "Return httpCode is {$httpCode} \n"
                . curl_error($curl) . "URL: " . $url;
            //echo $msg,nl2br("\n");
            // echo $msg.$errorresponse['Messages'][0];
            curl_close($curl);
            return $msg;
            //return $response;
        } else {
            curl_close($curl);
            return $response;
        }
    }

    static function httpGet($url, $data, $header, $grantType)
    {
        $tokenResponse = self::getToken($grantType);
        if (empty($tokenResponse['access_token'])) {
            throw new Exception("invalid grant"); 
        }

        self::AddOrReplaceKeyToHeader($header, 'Authorization', 'Bearer ' . $tokenResponse['access_token']);
        self::AddOrReplaceKeyToHeader($header, 'User-Agent', 'BasSdk');
        self::AddOrReplaceKeyToHeader($header, 'x-client-id', BasSdkService::getClientId());
        self::AddOrReplaceKeyToHeader($header, 'x-app-id', BasSdkService::getAppId());
        self::AddOrReplaceKeyToHeader($header, 'x-sdk-version', ConfigProperties::$CurrentVersion);
        self::AddOrReplaceKeyToHeader($header, 'x-environment', ConfigProperties::$environment);
        self::AddOrReplaceKeyToHeader($header, 'correlationId', self::GUID());
        self::AddOrReplaceKeyToHeader($header, 'x-sdk-type', 'php');

        //if($url)
        $curl = curl_init($url);

        //curl_setopt($curl, CURLOPT_POST, true);
        //curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 0);

        curl_setopt($curl, CURLOPT_HTTPHEADER, $header);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, 0);

        $response = curl_exec($curl);

        $httpCode = curl_getinfo($curl, CURLINFO_HTTP_CODE);

        if ($httpCode != 200) {
            $msg = "Return httpCode is {$httpCode} \n"
                . curl_error($curl) . "URL: " . $url;

            // echo $msg.$errorresponse['Messages'][0];
            curl_close($curl);
            return $msg;
        } else {
            curl_close($curl);

            return $response;
        }
    }
     static function AddOrReplaceKeyToHeader(&$headers, $key, $value) {
        // Check if the header key already exists
        if (array_key_exists($key, $headers)) {
            // Replace the existing value
            $headers[$key] = $value;
        } else {
            // Add new header
            $headers[$key] = $value;
        }
    }
    



    /**
     * Implement changes based on updates to Bas Sdk in C#
     *
     *
     */

    public static function Initialize(ENVIRONMENT $environment, string $clientId, string $clientSecret, string $appId, string $openId, string $mKey): void
    {
        ConfigProperties::SetEnvironment(environment: $environment);
        self::SetClientId(clientId: $clientId);
        self::SetClientSecret(clientSecret: $clientSecret);
        self::SetAppId($appId);
        self::SetOpenId($openId);
        self::SetMKey(mKey: $mKey);
    }

    /**
     * Get UserInfo V2 
     *
     * @param  string  $code
     * 
     */

   

    /**
     * 
     * Get full baseUrl of API
     */

    static function GetFullBaseUrlBasedOnEnvironment($relativePath): string
    {
        $baseUrl = "";
        //echo "Current env: ". ConfigProperties::$environment->value;
        switch (ConfigProperties::$environment) {
            case ENVIRONMENT::STAGING:
                $baseUrl = ConfigProperties::$baseUrlStaging . $relativePath;
                return $baseUrl;
            case ENVIRONMENT::PRODUCTION:
                $baseUrl = ConfigProperties::$baseUrlProduction . $relativePath;
                return $baseUrl;
            case ENVIRONMENT::SANDBOX:
                $baseUrl = ConfigProperties::$BaseUrlSandbox . $relativePath;
                return $baseUrl;
            default:
                throw new InvalidArgumentException("BASSDK.UnKnown Environment" . ConfigProperties::$environment->value);
        }
    }

    /**
     * Set the openId during initialization.
     *
     * @param  int  $openId
     * 
     */
    private static function SetOpenId(string $openId): void
    {
        if (empty($openId)) {
            throw new InvalidArgumentException("BASSDK.SetOpenId openId is null");
        }
        ConfigProperties::$openId = $openId;
    }

    /**
     * Set the appId during initialization.
     *
     * @param  int  $appId
     * 
     */
    private static function SetAppId(string $appId): void
    {
        if (empty($appId)) {
            throw new InvalidArgumentException("BASSDK.SetAppId appId is null");
        }
        ConfigProperties::$appId = $appId;
    }

    /**
     * Set the mKey during initialization.
     *
     * @param  int  $mKey
     * 
     */
    private static function SetMKey(string $mKey): void
    {
        //if (!self::isSandboxEnvironment() && empty($mKey)) {
            if (!self::isSandboxEnvironment() && $mKey === null) {
            throw new InvalidArgumentException("BASSDK.SetmKey mKey is null");
        }
        ConfigProperties::$mKey = $mKey;
    }

    /**
     * Set the clientId during initialization.
     *
     * @param  int  $clientId
     * 
     */
    private static function SetClientId(string $clientId): void
    {
        if (empty($clientId)) {
            throw new InvalidArgumentException("BASSDK.SetClientId clientId is null");
        }
        ConfigProperties::$clientId = $clientId;
    }
    /**
     * Set the clientSecret during initialization.
     *
     * @param  int  $clientSecret
     * 
     */
    private static function SetClientSecret(string $clientSecret): void
    {
        if (empty($clientSecret)) {
            throw new InvalidArgumentException("BASSDK.SetClientSecret clientSecret is null");
        }
        ConfigProperties::$clientSecret = $clientSecret;
    }


    /**
     * Get the appId .
     *
     * @return  string  $appId
     * 
     */
    public static function GetOpenId(): string
    {
        if (empty(ConfigProperties::$openId)) {
            throw new InvalidArgumentException("BASSDK.GetOpenId openId is null");
        }
        return ConfigProperties::$openId;
    }


    /**
     * Get the appId .
     *
     * @return  string  $appId
     * 
     */
    public static function GetAppId(): string
    {
        if (empty(ConfigProperties::$appId)) {
            throw new InvalidArgumentException("BASSDK.SetAppId appId is null");
        }
        return ConfigProperties::$appId;
    }

    /**
     * Get the appId .
     *
     * @return  string  $appId
     * 
     */
    public static function GetMKey(): string
    {
        if (empty(ConfigProperties::$mKey)) {
            throw new InvalidArgumentException("BASSDK.GetMKey mKey is null");
        }
        return ConfigProperties::$mKey;
    }

    /**
     * Get the ClientId .
     *
     * @return  string  $clientId
     * 
     */
    public static function GetClientId(): string
    {
        if (empty(ConfigProperties::$clientId)) {
            throw new InvalidArgumentException("BASSDK.GetClientId ClientId is null");
        }
        return ConfigProperties::$clientId;
    }

    /**
     * Get the ClientSecret .
     *
     * @return  string  $clientSecret
     * 
     */
    public static function GetClientSecret(): string
    {
        if (empty(ConfigProperties::$clientSecret)) {
            throw new InvalidArgumentException("BASSDK.SetClientsecret clientsecret is null");
        }
        return ConfigProperties::$clientSecret;
    }

    // public static function GetEnvironment(): mixed
    // {
    //     if (ConfigProperties::$environment !== null) {
    //         return ConfigProperties::$environment->value;
    //     } else {
    //         throw new Exception("Environment is not initialized.");
    //     }
    // }

    public static function GetAuthRedirectUrl(): string
    {
        if (empty(ConfigProperties::$redirectUrl)) {
            throw new InvalidArgumentException("BASSDK.GetAuthRedirectUrl RedirectUrl is null");
        }
        return self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$redirectUrl);
    }

    public static function GetuserInfoUrlV2(): string
    {
        if (empty(ConfigProperties::$userInfoV2Url)) {
            throw new InvalidArgumentException("BASSDK.GetuserInfoV2Url userInfoV2Url is null");
        }
        return self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$userInfoV2Url);
    }

    public static function GetInitiatePaymentUrl(): string
    {
        if (empty(ConfigProperties::$initiatePaymentUrl)) {
            throw new InvalidArgumentException("BASSDK.GetInitiatePaymentUrl initiatePaymentUrl is null");
        }
        return self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$initiatePaymentUrl);
    }

    public static function GetPaymentStatusUrl(): string
    {
        if (empty(ConfigProperties::$paymentStatusUrl)) {
            throw new InvalidArgumentException("BASSDK.GetPaymentStatusUrl paymentStatusUrl is null");
        }
        return self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$paymentStatusUrl);
    }
    private static function GetTokenUrl(): string
    {
        if (empty(ConfigProperties::$tokenUrl)) {
            throw new InvalidArgumentException("BASSDK.GetTokenUrl tokenUrl is null");
        }
      //  ini_set('memory_limit', '-1');
        return self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$tokenUrl);
    }
    public static function GetMobileFetchAuthUrl(): string
    {
        if (empty(ConfigProperties::$mobileFetchAuthUrl)) {
            throw new InvalidArgumentException("BASSDK.GetMobileFetchAuthUrl mobileFetchAuthUrl is null");
        }
        return self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$mobileFetchAuthUrl);
    }

    public static function GetMobilePaymentUrl(): string
    {
        if (empty(ConfigProperties::$mobilePaymentUrl)) {
            throw new InvalidArgumentException("BASSDK.GetMobilePaymentUrl mobilePaymentUrl is null");
        }
        return self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$mobilePaymentUrl);
    }

   
    public static function GetEnvironment(): mixed
    {
        if (ConfigProperties::$environment !== null) {
            return ConfigProperties::$environment->value;
        } else {
            throw new Exception("Environment is not initialized.");
        }
    }
   

    //TODO
    public static function isSandboxEnvironment()
    {
        if (ConfigProperties::$environment == ENVIRONMENT::SANDBOX) {
            return true;
        }
        return false;
    }
    public static function GUID()
    {
        if (function_exists('com_create_guid') === true)
        {
            return trim(com_create_guid(), '{}');
        }
    
        return sprintf('%04X%04X-%04X-%04X-%04X-%04X%04X%04X', mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(16384, 20479), mt_rand(32768, 49151), mt_rand(0, 65535), mt_rand(0, 65535), mt_rand(0, 65535));
    }


    // public static function SendNotificationToCustomer($templateName, $orderId, $orderParams, $firebasePayload, $extraPayload): mixed
    // {
    //     $accessToken = self::getToken();
    //     if (!is_null($accessToken)) {
    //         throw new InvalidArgumentException("BASSDK.SendNotificationToCustomer accessToken is null");
    //     }
    //     $header = array();
    //     $header['Authorization'] = $accessToken;
    //     $header['scheme'] = 'Bearer';
    //     $header['AppId'] = self::GetAppId();

    //     $data = array();
    //     $data['orderId'] = $orderId;
    //     $data['extraPayload'] = $extraPayload;
    //     $data['firebasePayload'] = $firebasePayload;
    //     $data['orderParams'] = $orderParams;
    //     $data['templateName'] = $templateName;

    //     $body = http_build_query($data);
    //     $url = self::GetFullBaseUrlBasedOnEnvironment(ConfigProperties::$notificationUrl);
    //     $response = self::httpPost($url, $body, header: $header);
    //     return json_decode($response, true);
    // }

   
}
// #region Config 
class  ConfigProperties
{

    public static  $CurrentVersion = "3.0.4";
    public static $openId;
    public static $mKey;
    public static $appId;
    public static $clientId;
    public static $clientSecret;
    public static ENVIRONMENT $environment;
    //public static ?ENVIRONMENT $environment = null; 
    public static  $BaseUrlSandbox = "https://basgate-sandbox.com";
    public static  $baseUrlStaging = "https://api-tst.basgate.com:4951";
    public static  $baseUrlProduction = "https://api.basgate.com:4950";
    public static  $redirectUrl = "/api/v1/auth/callback";
    public static  $userInfoV2Url = "/api/v1/auth/secure/userinfo";
    public static  $initiatePaymentUrl = "/api/v2/merchant/secure/transaction/initiate";
    public static  $paymentStatusUrl = "/api/v2/merchant/secure/transaction/status";
    public static  $notificationUrl = "/api/v1/merchant/secure/notifications/send-to-customer";
    public static  $tokenUrl = "/api/v1/auth/token";
    public static  $mobileFetchAuthUrl = "/api/v1/mobile/fetchAuth";
    public static  $mobilePaymentUrl = "/api/v1/mobile/payment";
    public static bool $isInitialized = false;

    
    public static function SetEnvironment(ENVIRONMENT $environment): void
    {
        if (empty($environment->value)) {
            throw new InvalidArgumentException("BASSDK.SetEnvironment environment is null");
        }
        self::$environment = $environment;
    }
}
class GrantTypes {
    const authorization_code = 'authorization_code';
    const client_credentials = 'client_credentials';
}
enum ENVIRONMENT: string
{
    case STAGING = 'staging';
    case PRODUCTION = 'production';
    case SANDBOX = 'sandbox';
}

// #endregion