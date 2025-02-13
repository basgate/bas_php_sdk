<?php

use PSpell\Config;

include(dirname(__DIR__) . '../Services/BasSDKService.php');
include(dirname(__DIR__) . '../Initialization.php');

$initial = Initialization::getInstance();
$initial->Initialize(ENVIRONMENT::STAGING);
?>
<!DOCTYPE html>
<html>

<head>
    <script src="../bassdk.js" type="text/javascript"></script>
    <title>Bas SDK</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>

<body style="text-align:left;font-size:3vw">
    <?php
    require_once '../Services/BasSDKService.php';
    ?>
    <h1 style="color:deeppink;">Bas SDK</h1>

    <form method="post">
        <?php if (BasSDKService::GetEnvironment() !== Environment::SANDBOX): ?>
            <div style="text-align: center;">
                <!-- Buttons for non-sandbox environments -->
                <input type="submit" name="login" class="button" value="Login" />
                <input type="submit" name="user_info" class="button" value="User Info" />
                <input type="submit" name="initiate_payment" class="button" value="Initiate Payment" />
                <input type="submit" name="check_payment_status" class="button" value="Check Payment Status" />
            </div>
        <?php endif; ?>
    
        <?php if (BasSDKService::GetEnvironment() === Environment::SANDBOX): ?>
            <br>
            <br>
            <div style="text-align: center;">
                <h4>SandBox Environment</h4>
            </div>
            <br>
            <div style="text-align: center;">
                <!-- Buttons for sandbox environment -->
                <input type="submit" name="simulate_userinfo" class="button" value="Simulate UserInfo" />
                <input type="submit" name="simulate_payment" class="button" value="Simulate Payment" />
            </div>
        <?php endif; ?>
    </form>
    
<?php



// Handle the form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (array_key_exists('login', $_POST)) {
        login();
    } else if (array_key_exists('user_info', $_POST)) {
        UserInfo();
    } else if (array_key_exists('initiate_payment', $_POST)) {
        InitiatePayment();
    } else if (array_key_exists('check_payment_status', $_POST)) {
        CheckPaymentStatus();
    }
}

// PHP Functions

function login()
{
    if (BasSDKService::GetEnvironment() !== ENVIRONMENT::SANDBOX) {
        if (isset($_COOKIE['isInBasSuperApp'])) {
?>
            <script>
                var clientId = <?php echo BasSDKService::GetClientId(); ?>;
                var x = await oauthToken(clientId);
            </script>
<?php
        }
    }
}



function UserInfo()
{
    $authCode = isset($_COOKIE['AuthCode']) ? $_COOKIE['AuthCode'] : null;
    if (!is_null($authCode)) {
        echo "AuthCode: " . htmlspecialchars($authCode) . nl2br("\n");

        $user_response = BasSDKService::GetUserInfo($authCode);
        if (is_null($user_response)) {
            echo "GetUserInfo: Status= 0\nError Can't get Token";
            return;
        }

        $user_status = $user_response['status'];
        if ($user_status == 1) {
            $user_name = $user_response['data']['user_name'];
            echo "GetUserInfo: Status= " . $user_status . " User_Name: " . $user_name;
        } else {
            echo "GetUserInfo: Status= " . $user_status . " Code: " . $user_response['code'];
        }
    } else {
        echo "AuthCode cookie not found.";
    }
}

function InitiatePayment()
{
    $callBackUrl = "";
    $orderid = (string) time();
    $amount = rand(100, 10000);
    $customerInfoId = "75b32f99-5fe6-496f-8849-a5dedeb0a65f";
    $order = BasSDKService::InitPayment($orderid, $amount, $callBackUrl, customerInfoId: $customerInfoId);

    echo "<pre>";
    print_r($order);
    echo "</pre>";
}

function CheckPaymentStatus()
{
    $orderid = "1729191828";
    $order_status = BasSDKService::CheckPaymentStatus($orderid);

    echo "<pre>";
    print_r($order_status);
    echo "</pre>";
}

?>

</body>

</html>