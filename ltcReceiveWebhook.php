<?php
/*
|--------------------------------------------------------------------------
| Multicoin webhooks (Copy and change name for other coins EG: btcReceiveWebhook.php for BCH)
|--------------------------------------------------------------------------
|
| You need to create webhooks for eeach coin listed on the multipayment page 
| The file can be on any name but kindly set the file complete url on each coin on BitGo.com
| Mean if you have five coin listed on the multipage you need to have 5 webhooks with different name. 
| Please contact for support if you need help https://maylancer.org/contact/
| 
|
*/


require 'inc/init.php';


// get database connection
$product         = new Product();

$coin        = CurrencyCode::LITECOIN;// Change this to the currency you want to use list of supported Const inc/bitgo/CurrencyCode.php 
$bitGo_api   = Config::get('app:bitgo_api_key');

$bitgo           = new BitGoSDK($bitGo_api, $coin, Config::get('app:bitgo_env') === 'prod' ? false : true ); 
$bitgo->walletId = Config::get('app:bitgo.wallet_'.$coin);


$payload         = $bitgo->getWebhookPayload();

$txDetails       = $bitgo->getWalletTransaction($payload['hash']);


if (isset($txDetails['error'])) {
    exit($txDetails['error']);
}

if (!isset($txDetails['fromWallet']))
{

    foreach ($txDetails['outputs'] as $outputs)
    {
        if (isset($outputs['wallet']))
        {
            $output = ['address' => $outputs['address'], 'value' => $outputs['value']];

            //check if transaction with wallet address exist from the database.
            $wallet = $outputs['address'];
            $CheckStatus = $product->readOne($wallet);

        }

    }

    //Now check if invoice has data
    if (!$CheckStatus)
    {
        return;
    }

    $amountBTC = $bitgo->toBTC($output['value']);     //grab the bitcoin value
    $amountUSD = $bitgo->FormatUSD($amountBTC);       //convert bitcoin value to usd
    $data = ['received' => $amountBTC, 'usdamount' => $amountUSD, 'txid' => $payload['hash'], 'confirmations' => $txDetails['confirmations'], 'address' => $output['address'], ];

    if ($amountBTC > 0 && $txDetails['confirmations'] >= 1)
    {

        /*
        |--------------------------------------------------------------------------
        | Payment confirmed (1 bitcoin confirmation as seen above)
        |--------------------------------------------------------------------------
        |
        | You can write other rules here such as order confirmations, produect delivery, email confirmation
        | 
        |
        | Please see documentation for more information about this section. 
        |
        */



        // set product property values
        $data = [
            'amount'        => $amountBTC,
            'amountUSD'     => $amountUSD, 
            'txtid'         => $data['txid'],
            'dateConfirmed' => date('Y-m-d H:i:s'),
            'dateReceived'  => date('Y-m-d H:i:s'),
            'status'        => 1,

         ];   

        // update the product
        $product->update($data, $data['address']);

    }
    else
    {

        /*
        |--------------------------------------------------------------------------
        | Payment  Pending confirmed (0 Confirmations)
        |--------------------------------------------------------------------------
        |
        | You can write other rules here such as order pending notifications, invoice processed, notification email
        | schemes.
        |
        | Please see documentation for more information about this section. 
        |
        */
        $data = [
            'amount'        => $amountBTC,
            'amountUSD'     => $amountUSD, 
            'txtid'         => $data['txid'],
            'dateConfirmed' => date('Y-m-d H:i:s'),
            'dateReceived'  => date('Y-m-d H:i:s'),
            'status'        => 2,

         ];   
         
        // update the product
        $product->update($data, $data['address']);
    }

}
else
{
  exit('No transaction detected');
    
}