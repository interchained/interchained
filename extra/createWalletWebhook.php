<?php

require '../inc/init.php';

$coin        = Config::get('app:coin');
$bitGo_api   = Config::get('app:bitgo_api_key');

$bitgo           = new BitGoSDK($bitGo_api, $coin, Config::get('app:bitgo_env') === 'prod' ? false : true ); 
$bitgo->walletId = Config::get('app:wallet_Id');


$url  = Config::get('app:url')."/receiveWebhook.php"; //path to your webhook file receiveWebhook.php update your website url on the config file inc/config.php
$type = "transfer";      //Type of event to listen to (can be 'transfer' or 'pendingaapproval').
$numConfirmations = 0;
$data = $bitgo->addWalletWebhook($url,$type, $numConfirmations);


if (isset($data['state']) &&  !isset($data['error'])) {
	echo 'A wallet webhook has been created for 0 Confirmations<br><br>';
}else{
	echo '1) Whoops! There was an error : '.$data['error'].'<br>';
}



$numConfirmations = 1;
$confirmed = $bitgo->addWalletWebhook($url,$type, $numConfirmations);


if (isset($confirmed['state']) && !isset($confirmed['error'])) {
	echo 'A wallet webhook has been created for 1 Confirmations to update user payment of payment succesfully received and confirmed<br>';
}else{
	echo '2) Whoops! There was an error : '.$data['error'].'<br>';
}
