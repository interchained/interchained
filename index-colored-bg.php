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

    <title>Payment Page</title>
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="assets/vendor/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="assets/css/style.css">
    <link href="assets/vendor/fontawesome/css/all.css" rel="stylesheet">

    <?php $color = Config::get('app:color_scheme'); ?>
        <link href="<?php echo asset_url("css/colors/{$color}.css") ?>" rel="stylesheet" id="color_scheme">

        <!--load all styles -->
</head>

<body class="checkout-background">

    <div class="container">

        <div class="row">
            <div class="col-md-8 col-sm-12 mx-auto mt-5">

                <div class="card mt-5">
                    <ul class="list-group">
                        <li class="list-group-item">
                            <center>
                                <img data-toggle="tooltip" data-placement="bottom" title="QR Code - Bitcoin address and sum you can scan with a mobile phone camera. Open Bitcoin Wallet, click on camera icon, point the camera at the code, and you're done" class="qr-display" src="https://chart.googleapis.com/chart?chs=125x125&cht=qr&chl=<?php echo sanitize_str($bitgo->CoinFullName($coin)); ?>:<?php echo sanitize_str($payWallet); ?>?amount=<?php echo sanitize_float($amount); ?>&choe=UTF-8">

                                <strong>Invoice</strong> 
                                <span class="text-green"><span>#<?php echo sanitize_str($invoiceID); ?></span> 
                                <span class="text-dark"><strong>Price: </strong></span> 
                                <span> $<?php echo sanitize_str($dollar); ?></span>
                              </span>
                            </center>
                        </li>
                        <li class="list-group-item">
                            <div class="pay-block">
                                <div class="row">
                                    <div class="col-3">
                                        <div class="sc2-label">Amount Remaining</div>
                                        <div><a class="copyImg" data-clipboard-target="#amount" id="copyImg" data-toggle="tooltip" data-placement="top" title="Copy"><span id="amount"><?php echo sanitize_float($amount)?></span>  <span id="coin"><?php echo sanitize_str(strtoupper($coin)); ?></span></a></div>
                                    </div>
                                    <div class="col-1">
                                        <div class="invis sc2-label">To</div>
                                        <div class="send-icon"><i class="fa fa-angle-right" aria-hidden="true"></i></div>
                                    </div>
                                    <div class="col-6">
                                        <div class="sc2-label">Address</div>
                                        <div class="address owl block"><span class="copyWallet" id="copyWallet" data-original-title="Copy Wallet" data-clipboard-target="#wallet" data-placement="bottom" data-toggle="tooltip">
                  <spam id="wallet"><?php echo sanitize_str($payWallet); ?></span>
                                            </spam>
                                        </div>
                                    </div>
                                    <div class="col-2">
                                        <div class="algnlft sc2-label">Time Left</div>
                                        <div class="timer-b text-left"> <span id="timerData"><span id="staticTime"><?php echo gmdate('i:s', sanitize_float($product->invoice_time)); ?></span><span id="timer" data-seconds-left="<?php echo sanitize_float($product->invoice_time); ?>"></span></span>
                                        </div>
                                    </div>
                                </div>
                                <div class="mt-2" id="tips">
                                    Make sure to send enough to cover any coin transaction fees! </div>
                                <div class="checkout-grey sct">
                                    Payment ID:
                                    <?php echo sanitize_str($paymentID); ?>
                                </div>
                                <br>
                                <div id="paymentStat"></div>
                            </div>
                        </li>
                        <li class="list-group-item spoiler-block">
                            <div class="accordion" id="accordion" role="tablist" aria-multiselectable="true">

                                <div role="tab" id="headingOne">

                                    <a data-toggle="collapse" data-parent="#accordion" href="#collapseOne" aria-expanded="true" aria-controls="collapseOne" class="owl text-decoration-none">What to do next? 
        </a>
                                </div>
                                <div id="collapseOne" class="panel-collapse collapse in" role="tabpanel" aria-labelledby="headingOne">
                                    <div class="panel-body">
                                        1) Please send <strong><?php echo sanitize_float($amount)?> <?php echo sanitize_str(strtoupper($coin)); ?></strong> to address <strong><?php echo sanitize_str($payWallet); ?></strong>. (Make sure to send enough to cover any coin transaction fees!) You will need to initiate the payment using your software or online wallet and copy/paste the address and payment amount into it.
                                        <br> &nbsp;&nbsp;&nbsp;&nbsp;i) The transaction ID:
                                        <?php echo sanitize_str($paymentID); ?>
                                            <br> &nbsp;&nbsp;&nbsp;&nbsp;ii) A payment address to send the funds to.
                                            <br> 2) After sending payment, your purchase will be confirmed automatically without reloading this page</a>. Once the payment is confirmed several times in the block chain, the payment will be completed immediately. <b>The confirmation process usually takes 10-45 minutes but varies based on the coin's target block time and number of block confirms required.</b>
                                    </div>
                                </div>

                            </div>

                        </li>
                        <li class="list-group-item spoiler-block">
                            <div class="accordion" id="accordion" role="tablist" aria-multiselectable="true">

                                <div role="tab" id="headingTwo">

                                    <a data-toggle="collapse" data-parent="#accordion" href="#collapsetwo" aria-expanded="true" aria-controls="collapsetwo" class="text-decoration-none">What if I accidentally don't send enough?  
        </a>
                                </div>
                                <div id="collapsetwo" class="panel-collapse collapse in" role="tabpanel" aria-labelledby="headingTwo">
                                    <div class="panel-body">
                                        If you don't send enough, that is OK. Just send the remainder and we will combine them for you. You can also send from multiple wallets/accounts.
                                    </div>
                                </div>
                            </div>

                        </li>
                    </ul>

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