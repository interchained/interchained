<?php

//Set global variables for you site configurations
$GLOBALS['config'] = array(
    
    'app' => array(



        /*
        |--------------------------------------------------------------------------
        | Debug Mode
        |--------------------------------------------------------------------------
        |
        | When enabled the actual PHP errors will be shown.
        | If disabled, a simple generic error message is shown.
        |
        */ 

        'debug' => true,

        /*
        |--------------------------------------------------------------------------
        | Website URL
        |--------------------------------------------------------------------------
        | 
        | This URL is used in emails, page redirects and webhook.
        | You must set this to the root of the script without slash full file path
        |
        */

        'url' => 'http://localhost/bitgo-payment',

        
        /*
        |--------------------------------------------------------------------------
        | Website IP ADDRESS
        |--------------------------------------------------------------------------
        |
        | Your website/server ip address. (Leave blank the default value on localhost test)
        |
        */
        'server_ip_address' => '165.22.14.213',
        
        /*
        |--------------------------------------------------------------------------
        | BitGo API Key
        |--------------------------------------------------------------------------
        |
        | Your BitGo unique API Key (Should be 69 alphanumeric character long)
        |
        */
        'bitgo_api_key' => 'v2xc4ac6e1d110147ec90a9260d468850ef2b407f93396ddbb7d9d68d26a73c93e7',
        
        /*
        |--------------------------------------------------------------------------
        | BitGo Wllet ID
        |--------------------------------------------------------------------------
        |
        | Your BitGo Wallet ID from the wallet settings
        |
        */
        'wallet_Id' => '5d7aeef0870e5865038a8883ce8cae30', 

   
        /*
        |--------------------------------------------------------------------------
        | BitGo Wllet ID For multiple coin only
        |--------------------------------------------------------------------------
        |
        | This section is for multiple coin only.
        |
        */
        
        'wallet_btc' => '5ea4ba45f6bf288028f386f13840cd32',
        'wallet_ltc' => '5eaa11339e9657d507b0ab532eeee322',
        'wallet_bch' => '5eaa1110d2beded00769415e076bb771',
        'wallet_dash' => '5ec47e16ed7be31f005487001aa39ff0',
        'wallet_xlm' => '5ec5c3224ebdb234003132b1b7f39d01',




        /*
        |--------------------------------------------------------------------------
        | Multi-coin BitGo Coins
        |--------------------------------------------------------------------------
        | Select the coin what you want to use with the BitGOSDK (use CurrencyCode class to select)
        | See supported coin 'btc', 'bch', 'bsv', 'btg', 'dash', 'ltc', 'xrp', 'zec', 'rmg', 'xlm', 'erc', 'omg', 'zrx', 'fun', 'gnt', 'rep', 'bat', 'knc', 'cvc', 
        | 'eos', 'qrl', 'nmr', 'pay', 'brd', 'tbtc', 'tbch', 'tbsv', 'tdash', 'tltc', 'txrp', 'tzec', 'trmg', 'terc'
        |
        */
        'coins'  => array(
          'btc'  => 'Bitcoin',
          'bch'  => 'Bitcoin Cash',
          'ltc'  => 'Litecoin',
          'dash' => 'Dash',
          'xlm'  => 'Stellar',
         ),

        
        
        /*
        |--------------------------------------------------------------------------
        | Single BitGo Coin 
        |--------------------------------------------------------------------------
        | Select the coin what you want to use with the BitGOSDK (use CurrencyCode class to select)
        | See supported coin 'btc', 'bch', 'bsv', 'btg', 'dash', 'ltc', 'xrp', 'zec', 'rmg', 'erc', 'xlm', 'omg', 'zrx', 'fun', 'gnt', 'rep', 'bat', 'knc', 'cvc', 
        | 'eos', 'qrl', 'nmr', 'pay', 'brd', 'tbtc', 'tbch', 'tbsv', 'tdash', 'tltc', 'txrp', 'tzec', 'trmg', 'terc'
        |
        */
        'coin' => 'tbtc',
        
        
        
        /*
        |--------------------------------------------------------------------------
        | BitGo BITGO_PRODUCTION_API_ENDPOINT
        |--------------------------------------------------------------------------
        |
        | Start instance as testnet (test or prod), default is false
        |
        */
        'bitgo_env' => 'test',
        
        
        
        
        /*
        |--------------------------------------------------------------------------
        | Payment Process Fees
        |--------------------------------------------------------------------------
        |
        | If you use the script with payment fees you can set the payment fees 
        | Below
        | 
        |
        |
        */
        'fees' => '0.5',
        
        
        /*
        |--------------------------------------------------------------------------
        | invoice Expiring time
        |--------------------------------------------------------------------------
        |
        | set invoice expiring time milleseconds 
        |
        */
        
        'expiring_time' => 43200,



        /*
        |--------------------------------------------------------------------------
        | Website Color Scheme
        |--------------------------------------------------------------------------
        |
        | If you use the script with its design you can choose from multiple color
        | schemes.
        |
        | Supported: "dark", "light", "blue", "coffee", "ectoplasm", "midnight"
        |
        */

        'color_scheme' => 'blue',


        /*
        |--------------------------------------------------------------------------
        | Timezone
        |--------------------------------------------------------------------------
        |
        | The default timezone for your website.
        | http://www.php.net/manual/en/timezones.php
        |
        */

        'timezone' => 'UTC',
            
        
        
    ),
    
    //Mysql Database connection
    'mysql' => array(
        
        /*
        |--------------------------------------------------------------------------
        | Database Name
        |--------------------------------------------------------------------------
        */
        
        'database' => 'crypto_box',
        
        /*
        |--------------------------------------------------------------------------
        | Database Username
        |--------------------------------------------------------------------------
        */
        
        'username' => 'root',
        
        /*
        |--------------------------------------------------------------------------
        | Database Password
        |--------------------------------------------------------------------------
        */
        
        'password' => '',
        
        /*
        |--------------------------------------------------------------------------
        | Database Hostname
        |--------------------------------------------------------------------------
        */
        
        'hostname' => 'localhost',
        
        /*
        |--------------------------------------------------------------------------
        | Database Table Prefix
        |--------------------------------------------------------------------------
        */
        
        'prefix' => '',
        
        /*
        |--------------------------------------------------------------------------
        | Database Driver
        |--------------------------------------------------------------------------
        */
        
        'driver' => 'mysqli',
        
        /*
        |--------------------------------------------------------------------------
        | Database Charset
        |--------------------------------------------------------------------------
        */
        
        'charset' => 'utf8mb4',
        
        /*
        |--------------------------------------------------------------------------
        | Database Collation
        |--------------------------------------------------------------------------
        */
        
        'collation' => 'utf8mb4_unicode_ci'
    )
    
);

class Config
{
    /**
     * Get a particular value back from the config array
     * @global array $config The config array defined in the config files
     * @param string $index The index to fetch in dot notation
     * @return mixed
     */
    public static function get($index)
    {
        global $config;
        $index = explode(':', $index);
        return self::getValue($index, $config);
    }
    /**
     * Navigate through a config array looking for a particular index
     * @param array $index The index sequence we are navigating down
     * @param array $value The portion of the config array to process
     * @return mixed
     */
    private static function getValue($index, $value)
    {
        if (is_array($index) and count($index)) {
            $current_index = array_shift($index);
        }
        if (is_array($index) and count($index) and is_array($value[$current_index]) and count($value[$current_index])) {
            return self::getValue($index, $value[$current_index]);
        } else {
            return $value[$current_index];
        }
    }
}
