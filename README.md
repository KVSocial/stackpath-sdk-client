# StackPath SDK / Client in PHP from Kyvio

This is a fork from https://github.com/newsdaycom/stackpath-php-sdk
It did not give us near enough functionality (e.g. lack of status code which is needed to check failure / success for various SP endpoints) 
hence we wrote this SDK and decided to share it.


Note this package was written in quite the haste :) 
This package is open source and we are open to pull requests for new features.

## Install

Add it by running:
    composer require kyvio/stackpath-sdk-client

## Configuration

You have to pass a config array like this:
$stackPath = [
    'stack_id' => '',
    'client_id' => '',
    'secret_id' => '',
    'ip_to_map' => '',
    'waf_options_off' => ['CSRF', 'Anti Scraping'],
]


## Use

try{
    $sp = new \StackPath\StackPath($stackPath);        
}
catch(\Exception $e){ 
    $msg = $e->getMessage(); 
    $this->warn($msg);            
}


## Docs
Check the PHPDoc in the class file.

Hope it helps you.