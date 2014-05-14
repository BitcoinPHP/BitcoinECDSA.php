Warning
===============

This piece of software is provided without warranty of any kind, use it at your own risk.

USAGE
===============

Instanciate
---------------------

    
    require_once("BitcoinECDSA.php");
    $bitcoinECDSA = new BitcoinECDSA();
    

Set a private key
---------------------

    
    $bitcoinECDSA->setPrivateKey($k);
    

Generate a random private key
---------------------
    
    $bitcoinECDSA->generateRandomPrivateKey($nonce);
    
The nonce is optional, typically the nonce is a set of random data you get from the user. For example mouse coordinates.
This adds randomless, which means the generated private key is stronger.

Get the private key
---------------------

    
    $bitcoinECDSA->getPrivateKey();
    

Get the Wif
---------------------

    
    $bitcoinECDSA->getWif();
    
returns the private key under the Wallet Import Format


Get the Public Key
---------------------

    
    $bitcoinECDSA->getPubKey();
    
The output is an array containing the X and Y coordinatinates of a point that is on the Elliptic Curve.

Get the Address
---------------------

    
    $bitcoinECDSA->getAddress();
    
Returns the uncompressed Bitcoin Address.


