<?php
/*
|--------------------------------------------------------------------------
| Set PHP Error Reporting
|--------------------------------------------------------------------------
*/

error_reporting(-1);


/*
|--------------------------------------------------------------------------
| Install Paths
|--------------------------------------------------------------------------
*/

$paths = array(
	'base' => __DIR__.'',
	'assets'  => __DIR__.'/../assets',
	'extra' => __DIR__.'/../extra'
);



/*
|--------------------------------------------------------------------------
| Set internal character encoding
|--------------------------------------------------------------------------
*/

if (function_exists('mb_internal_encoding')) {
	mb_internal_encoding('utf-8');
}








/*
|--------------------------------------------------------------------------
| Set PHP session if its not start already from your script 
|--------------------------------------------------------------------------
*/
if (session_status() == PHP_SESSION_NONE) {
    session_start();
}


/*
|--------------------------------------------------------------------------
| Composer Autoload
|--------------------------------------------------------------------------
*/
require_once $paths['base'] .'/whoops/vendor/autoload.php';
require_once $paths['base'] .'/bitcoin-currency-converter/vendor/autoload.php';
require_once $paths['base'] .'/database/vendor/autoload.php';
/*
|--------------------------------------------------------------------------
| Register Whoops Class Imports
|--------------------------------------------------------------------------
*/
$whoops = new \Whoops\Run;
use Whoops\Handler\PrettyPageHandler;
use Whoops\Handler\JsonResponseHandler;
use Whoops\Util\Misc;
use Whoops\Handler\HandlerInterface;





/*
|--------------------------------------------------------------------------
| Register Citcoin Currency Converter Class Imports
|--------------------------------------------------------------------------
*/

use Jimmerioles\BitcoinCurrencyConverter\Converter;
$convert = new Converter;








/*
|--------------------------------------------------------------------------
| Load Files requires
|--------------------------------------------------------------------------
*/

require_once('bitgo/lib.php');
require_once('bitgo/CurrencyCode.php');
require_once('bitgo/AddressType.php');
require_once('config.php');
require_once('database.php');
require_once('Product.php');
require_once('PlainDisplayer.php');
require_once('helpers.php');




/*
|--------------------------------------------------------------------------
| Set The Default Timezone
|--------------------------------------------------------------------------
*/

if (!empty(Config::get('app:timezone'))) {
	date_default_timezone_set(Config::get('app:timezone'));
}

/*
|--------------------------------------------------------------------------
| Register Custom Exception Handling
|--------------------------------------------------------------------------
*/

if (version_compare(PHP_VERSION, '5.5.9', '>=')) {
     
	/*
	|--------------------------------------------------------------------------
	| Set PHP Error Reporting
	|--------------------------------------------------------------------------
	*/
    startExceptionHandling($whoops);

    if (!Config::get('app:debug')) ini_set('display_errors', 'Off');
}














