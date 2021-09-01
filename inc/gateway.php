<?php
class BitgoGateway
{
    
    function display_cryptobox(int $amount)
    {
        global $bitgo;
        global $coin;
        global $database;
        global $db;
        global $product;
         
        
        
        
        $invoiceID  = $bitgo->invoiceID(12); //generate random invoice ID. this can be save to the database
        $fees      = Config::get('app:fees');          //custome transaction fees
        $dollar    = absint($amount + $fees); //Amount to be paid on USD
        $amount    = coin_format($dollar, $coin);       //get coin value base on select crypto-currency
        $ExpTime   = Config::get('app:expiring_time'); // payment wait time. 12 hours
        $remTime   = $bitgo->invoiceValidity($ExpTime); // payment wait time. 12 hours
        $paymentID = quickRandom(15);
        $_SESSION['btc_amount'] = $amount;
        /**/
        
        if ($coin == 'bch' || $coin == 'dash') {
        $createAddress = $bitgo->createWalletAddress(AddressType::LEGACY_DEPOSIT);
        }else if($coin =='zec'){
        $createAddress = $bitgo->createWalletAddress(AddressType::LEGACY_CHANGE);
        }else{
        $createAddress = $bitgo->createWalletAddress();
        }
        
        if (isset($createAddress['address']) && !isset($createAddress['error'])) {
            
            $payWallet               = $createAddress['address']; //New wallet address will be use and strored for the session only
            $_SESSION['pay_address'] = $createAddress['address'];
            // set product property values
          
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
        
        $_SESSION['btc_boxID'] = $invoiceID;
        $box                   = '<div class="panel panel-default" id="PaymentBox_' . sanitize_str($payWallet) . '">
            <div class="panel-body mb-5">
                <div class="row">
                    <div class="col-sm-12 col-md-12 col-lg-12">
                        <h3><span class="text text-warning"><img src="' . sanitize_str($bitgo->coinLogo($coin)) . '" width="32"></span> ' . sanitize_str(ucfirst($bitgo->CoinFullName($coin))) . ' Payment Box</h3>
                    </div>
                    <div class="col-sm-4 col-md-4 col-lg-4">
                        ' . $this->QRCode() . '
                    </div>
                    <div class="col-sm-8 col-md-8 col-lg-8 p-2">
                        <h3>Send <b><span id="amount">' . sanitize_float($amount) . '</span> <span id="coin">' . sanitize_str(strtoupper($coin)) . '</span></b> <img class="copyImg copy-img" id="copyImg" src="assets/img/copy.svg" data-clipboard-target="#amount"  data-toggle="tooltip" data-placement="top" title="Copy"></h3>

                        <br/><span id="copyWallet" class="copyWallet" data-original-title="Copy Wallet" data-clipboard-target="#address" data-placement="bottom" data-toggle="tooltip"><input type="text" id="address" class="form-control" value="' . sanitize_str($payWallet) . '"></span><spam class="display-hide" id="wallet">' . sanitize_str($payWallet) . '</spam>
                        or scan QR Code with your mobile device<br/><br/>
                        <small>If you send any other ' . sanitize_str(strtoupper($coin)) . ' amount, payment system will ignore it!</small>
                    </div>
                    <div class="col-sm-12 col-md-12 col-lg-12">
                        <center> <div id="paymentStat">
                                    <span class="text text-info"><i class="fa fa-spin fa-spinner"></i> Awaiting payment...</span>
                                </div></center>
                                <p class="card-text" id="tips"></p>
                    </div>
                </div>
            </div>
        </div>
        ';
        return $box;
    }
    
    function QRCode()
    {
        global $bitgo;
        global $coin;
        $address = $_SESSION['pay_address'];
        $amount  = $_SESSION['btc_amount'];
        return '<img data-toggle="tooltip" data-placement="bottom" title="QR Code - Bitcoin address and sum you can scan with a mobile phone camera. Open Bitcoin Wallet, click on camera icon, point the camera at the code, and you\'re done" src="https://chart.googleapis.com/chart?chs=500x500&cht=qr&chl=' . sanitize_str($bitgo->CoinFullName($coin)) . ':' . sanitize_str($address) . '?amount=' . sanitize_float($amount) . '&choe=UTF-8" class="img-responsive qr-display">';
    }
    
}

?>