<?php

require 'inc/init.php';

// get database connection
$product  = new Product();

$coin        = Config::get('app:coin');
$bitGo_api   = Config::get('app:bitgo_api_key');

$bitgo           = new BitGoSDK($bitGo_api, $coin, Config::get('app:bitgo_env') === 'prod' ? false : true ); 
$bitgo->walletId = Config::get('app:wallet_Id');


$invoiceID = $bitgo->invoiceID(12); //generate random invoice ID. this can be save to the database
$fees      = Config::get('app:fees');          //custome transaction fees
$dollar    = absint(10 + $fees); //Amount to be paid on USD //Amount to be paid on USD 
$amount    = coin_format($dollar, $coin);       //get coin value base on select crypto-currency
$ExpTime   = Config::get('app:expiring_time'); // payment wait time. 12 hours
$remTime   = $bitgo->invoiceValidity($ExpTime); // payment wait time. 12 hours
$paymentID = quickRandom(15);

 





    if ($coin == 'bch' || $coin == 'dash') {
     $createAddress = $bitgo->createWalletAddress(AddressType::LEGACY_DEPOSIT);
    }else if($coin =='zec'){
     $createAddress = $bitgo->createWalletAddress(AddressType::LEGACY_CHANGE);
    }else{
     $createAddress = $bitgo->createWalletAddress();
    }

if (isset($createAddress['address']) && !isset($createAddress['error'])) {
    //
    $_SESSION['pay_address']        = $createAddress['address']; //this could be session or added to the database
    $_SESSION['pay_address_ispaid'] = FALSE; //this could be session or directly from the database
    //
    $payWallet                      = $createAddress['address']; //New wallet address will be use and strored for the session only
    $remTime                        = $bitgo->invoiceValidity($ExpTime); // payment wait time. 2 hours
    
   
    // set product property values
    $data = [
        'user_id'   => 1, //replace with your session user id, this can be from the database
        'orderID' => $invoiceID,
        'productID' => $paymentID,
        'amount'    => $amount,
        'amountUSD'    => $dollar, 
        'boxType'   => 'product',
        'address' => $payWallet,
        'coinLabel'      => $coin,
        'invoice_time'   => $remTime,
        'txDate' => date('Y-m-d H:i:s'),

     ];   
        
    if ($product->create($data)) {
        // read the details of product to be edited
        $product = $product->readOne($payWallet);
       
    }
    // if unable to create the product, tell the user
    else {
        throw new \Exception('unable to create product table');
    }
    
    
} else {
    throw new \Exception($createAddress['error']);
}





?>

<!doctype html>
<html lang="en">

<head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <title>Custom Payment!</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="assets/vendor/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="assets/css/style.css">
    <link href="assets/vendor/fontawesome/css/all.css" rel="stylesheet">
    <!--load all styles -->
</head>

<body>
    <div class="container">
        <div class="row mt-5">
            <div class="col-md-6 mx-auto mt-5">
                <!-- Button trigger modal -->
                <h4 class="display-5">Lorem Ipsum is simply dummy checkout modal example</h4>
                <button type="button" class="btn btn-primary" data-toggle="modal" data-target="#exampleModal">Checkout modal</button>
            </div>
        </div>
        <!-- Modal -->
        <div class="modal fade" id="exampleModal" tabindex="-1" role="dialog" aria-labelledby="exampleModalLabel" aria-hidden="true">
            <div class="modal-dialog modal-lg" role="document">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title" id="exampleModalLabel">Bitcoin Payment</h5>
                        <button type="button" class="close" data-dismiss="modal" aria-label="Close"> <span aria-hidden="true">&times;</span>
                        </button>
                    </div>
                    <div class="modal-body">
                        <div class="row no-gutters">
                            <div class="col-md-4">
                                <center>
                                    <img data-toggle="tooltip" data-placement="bottom" title="QR Code - Bitcoin address and sum you can scan with a mobile phone camera. Open Bitcoin Wallet, click on camera icon, point the camera at the code, and you're done" class="qr-display" src="https://chart.googleapis.com/chart?chs=125x125&cht=qr&chl=<?php echo sanitize_str( $bitgo->CoinFullName($coin)); ?>:<?php echo sanitize_str($payWallet); ?>?amount=<?php echo sanitize_float($amount); ?>&choe=UTF-8">
                                </center>
                            </div>
                            <div class="col-md-8">
                                <div class="card-body">
                                    <h5 class="card-title">Custom Payment #<?php echo sanitize_str( $invoiceID); ?></h5>
                                    <hr>
                                    <h2 class="mb-2"><span id="amount"><?php echo sanitize_float($amount); ?></span> <?php echo sanitize_str(strtoupper($coin)); ?> <img class="copyImg copy-img" id="copyImg" src="assets/img/copy.svg" data-clipboard-target="#amount" data-toggle="tooltip" data-placement="top" title="Copy"></h2>
                                    <p class="card-text mt-2">Send
                                        <?php echo sanitize_float( $amount)?>
                                        <span id="coin"><?php echo sanitize_str(strtoupper($coin)); ?></span> (in ONE payment) to: don't include transaction fee in this amount</p>
                                    <h4 class="card-title wallet-text"><a class="copyWallet" id="copyWallet" data-original-title="Copy Wallet" data-clipboard-target="#wallet" data-placement="bottom" data-toggle="tooltip"><span id="wallet"><?php echo sanitize_str($payWallet); ?></span></a> </h4>
                                    <p class="card-text mt-2"></p>
                                    <br>
                                    </p>
                                    <p class="card-text" id="tips"><small class="text-muted">If you send any other <?php echo sanitize_str(strtoupper($coin)); ?> amount, payment system will ignore it!</small>
                                    </p>
                                </div>
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <div id="paymentStat"> <span class="text btn btn-block btn-secondary btn-lg disabled"><i class="fa-spin fas fa-circle-notch"></i> <span id="staticTime"><?php echo gmdate('i:s', sanitize_str($product->invoice_time)); ?></span><span id="timer" data-seconds-left="<?php echo sanitize_str( $product->invoice_time); ?>"></span></span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    <!-- Optional JavaScript -->
    <!-- jQuery first, then Popper.js, then Bootstrap JS -->
    <script src='assets/js/jquery.min.js'></script>
    <script src="assets/js/popper.min.js"></script>
    <script src="assets/vendor/bootstrap/js/bootstrap.min.js"></script>
      <!--Do not remove-->
    <script src="assets/js/clipboard.min.js"></script>
    <script src="assets/js/gateway.js"></script>
    <script src="assets/js/main.js"></script>
</body>

</html>