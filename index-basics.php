<?php

require 'inc/init.php';
require 'inc/gateway.php';


$product  = new Product();

$coin        = Config::get('app:coin');
$bitGo_api   = Config::get('app:bitgo_api_key');

$bitgo           = new BitGoSDK($bitGo_api, $coin, Config::get('app:bitgo_env') === 'prod' ? false : true ); 
$bitgo->walletId = Config::get('app:wallet_Id');


$dollar = absint(50); //product amount in USD


?>

<!doctype html>
<html lang="en">
  <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
       <title>Custom Payment!</title> 
    <!-- Bootstrap CSS -->
    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="assets/vendor/bootstrap/css/bootstrap.min.css">
    <link rel="stylesheet" href="assets/css/style.css">
    <link href="assets/vendor/fontawesome/css/all.css" rel="stylesheet">
    <!--load all styles -->
  </head>
  <body>
<div class="container">
   
<div class="row">
  <div class="col-md-8 col-sm-12 mx-auto mt-5 card">
<?php 
$box = new BitgoGateway();
echo $box->display_cryptobox($dollar);  //display payment box
?>
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

    
  </body>
</html>