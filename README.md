Warning
===============

This piece of software is provided without warranty of any kind, use it at your own risk.

USAGE
===============

**Instanciation**

    
    require_once("BitcoinECDSA.php");
    $bitcoinECDSA = new BitcoinECDSA();
    

**Set a private key**

    
    $bitcoinECDSA->setPrivateKey($k);
    
examples of private keys :

4C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D
00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC

**Generate a random private key**
    
    $bitcoinECDSA->generateRandomPrivateKey($nonce);
    
The nonce is optional, typically the nonce is a chunck of random data you get from the user. For example mouse coordinates.
This adds randomness, which means the generated private key is stronger.

**Get the private key**

    
    $bitcoinECDSA->getPrivateKey();
    
Returns the private key.

**Get the Wif**

    
    $bitcoinECDSA->getWif();
    
returns the private key under the Wallet Import Format


**Get the Public Key**

    
    $bitcoinECDSA->getPubKey();
    
Returns the compressed public key.

**Get the Address**

    
    $bitcoinECDSA->getAddress();
    
Returns the compressed Bitcoin Address.

**Get the uncompressed Address**

    
    $bitcoinECDSA->getUncompressedAddress();
    
Returns the uncompressed Bitcoin Address.

