<?php
header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Headers: access");
header("Access-Control-Allow-Methods: GET");
header("Access-Control-Allow-Credentials: true");
header('Content-Type: application/json');

require 'inc/init.php';


$product  = new Product();



if (isset($_GET['amount']) && is_numeric($_GET['amount']) && $_GET['amount'] != "" && isset($_GET['coin']) && $_GET['coin'] != "") {
    
    $amount_usd = isset($_GET['amount']) ? filter_var($_GET['amount'], FILTER_SANITIZE_NUMBER_INT) : 50; 
    $coin = isset($_GET['coin']) ? filter_var($_GET['coin'], FILTER_SANITIZE_STRING) : "btc"; 
    
    
    $bitGo_api   = Config::get('app:bitgo_api_key');

    $bitgo           = new BitGoSDK($bitGo_api, $coin, Config::get('app:bitgo_env') === 'prod' ? false : true );
    $bitgo->walletId = Config::get('app:wallet_'.$coin);

    
    $invoiceID = $bitgo->invoiceID(12);              //generate random invoice ID. this can be save to the database
    $fees      = Config::get('app:fees');          //custome transaction fees
    $dollar    = $amount_usd + $fees;              //invoice amount
    $getFees   = $bitgo->estimateTransactionFees();  // get recommended fee rate per kilobyte to confirm a transaction within a target number of blocks.
    $amount    = coin_format($dollar, $coin);       //get coin value base on select crypto-currency
    $ExpTime   = Config::get('app:expiring_time');   // payment wait time. 2 hours
    $remTime   = $bitgo->invoiceValidity($ExpTime);   // payment wait time. 2 hours
    $paymentID = $bitgo->invoiceID(15);
    
    
    
    
    
    
   
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
        
        //create array
        $response = array(
            "error" => $createAddress['error'],
            "status" => 0
            
        );
        // set response code - 200 OK
        http_response_code(200);
        
        // make it json format
        echo json_encode($response, JSON_PRETTY_PRINT);
        exit();
    }
    
    
    

// create array
    $response = array(
        "id" => $product->id,
        "user_id" => $product->user_id,
        "invoice" => $invoiceID,
        "payment_id" => $paymentID,
        "amount" => $amount,
        "address" => $payWallet,
        "dollar" => $dollar,
        "expiring" => $remTime,
        "coin" => strtoupper($coin),
        "coin_logo" => 'assets/img/'.$coin.'.png',
        "fees" => $fees,
        "qrcode" => "https://chart.googleapis.com/chart?chs=500x500&cht=qr&chl=bitcoin:" . $payWallet ."&choe=UTF-8",
        "qramount" => "https://chart.googleapis.com/chart?chs=500x500&cht=qr&chl=amount=" . $amount . "&choe=UTF-8",
        'created' => time_elapsed_string(date('Y-m-d H:i:s')),
        "status" => 1
        
    );
    
    // set response code - 200 OK
    http_response_code(200);
    
    // make it json format
    echo json_encode($response, JSON_PRETTY_PRINT);
    exit();
    
} else if (isset($_GET['invoice']) && $_GET['invoice'] != "") {
    
    $invoiceID = isset($_GET['invoice']) ? filter_var($_GET['invoice'], FILTER_SANITIZE_STRING) : "";

    $product = $product->readSingleProduct($invoiceID);
    if (!is_null($product->id)) {
        //create array
        $response = array(
            "id" => $product->id,
            "user_id" => $product->user_id,
            "invoice" => $product->orderID,
            "payment_id" => $product->productID,
            "amount" => $product->amount,
            "dollar" => $product->amountUSD,
            "address" => $product->address,
            "coin" => $product->coinLabel,
            "payment_type" => $product->boxType,
            "txt" => $product->txID,
            "date_confirmed" => $product->txConfirmed,
            "invoice_time" => $product->invoice_time,
            "paid" => $product->paid,
            "created" => $product->created,
            "status" => 1
            
        );
        // set response code - 200 OK
        http_response_code(200);
        
        // make it json format
        echo json_encode($response, JSON_PRETTY_PRINT);
        exit();
    } else {
        
        
        //create array
        $response = array(
            "error" => 'Invalid Invoice ID',
            "status" => 0
            
        );
        // set response code - 200 OK
        http_response_code(200);
        
        // make it json format
        echo json_encode($response, JSON_PRETTY_PRINT);
        exit();
        
        
    }
     
    
    
}else if (isset($_GET['coins']) && is_numeric($_GET['amount']) && $_GET['amount'] != "") {

   $amount_usd = isset($_GET['amount']) ? filter_var($_GET['amount'], FILTER_SANITIZE_NUMBER_INT) : 50; 

   echo json_encode(api_coins($amount_usd), JSON_PRETTY_PRINT);


} else {
    //create array
    $response = array(
        "error" => 'Bad request, no type specified.',
        "status" => 0
        
    );
    // set response code - 400 Bad Request
    http_response_code(400);
    
    // make it json format
    echo json_encode($response, JSON_PRETTY_PRINT);
    exit();
}
?>