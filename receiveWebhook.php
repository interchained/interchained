<?php
require 'inc/init.php';


// get database connection
$product         = new Product();

$coin        = Config::get('app:coin');
$bitGo_api   = Config::get('app:bitgo_api_key');

$bitgo           = new BitGoSDK($bitGo_api, $coin, Config::get('app:bitgo_env') === 'prod' ? false : true ); 
$bitgo->walletId = Config::get('app:wallet_Id');


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
            'txID'         => $data['txid'],
            'txConfirmed'   => date('Y-m-d H:i:s'),
            'txDate'        => date('Y-m-d H:i:s'),
            'paid'        => 1,

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
            'txID'         => $data['txid'],
            'txConfirmed'   => date('Y-m-d H:i:s'),
            'txDate'        => date('Y-m-d H:i:s'),
            'paid'        => 2,

         ];   
         
        // update the product
        $product->update($data, $data['address']);
    }

}
else
{
  exit('No transaction detected');
    
}

