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
    
The nonce is optional, typically the nonce is a chunck of random data you get from the user. This can be mouse coordinates.
Using a nonce adds randomness, which means the generated private key is stronger.

**Get the private key**

    
    $bitcoinECDSA->getPrivateKey();
    
Returns the private key.

**Get the Wif**

    
    $bitcoinECDSA->getWif();
    
returns the private key under the Wallet Import Format


**Get the Public Key**

    
    $bitcoinECDSA->getPubKey();
    
Returns the compressed public key.
The uncompressed PubKey starts with 0x02 if it's y coordinate is even and 0x03 if it's odd, the next 32 bytes corresponds to the x coordinates.

Example : 0226c50013603b085fbc26411d5d7e564b252d88964eedc4e01251d2d495e92c29

**Get the Uncompressed Public Key**

    
    $bitcoinECDSA->getUncompressedPubKey();
  
Returns the The uncompressed PubKey.
The uncompressed PubKey starts with 0x04, the next 32 bytes are the x coordinates, the last 32 bytes are the y coordinates.

Example : 04c80e8af3f1b7816a18aa24f242fc0740e9c4027d67c76dacf4ce32d2e5aace241c426fd288a9976ca750f1b192d3acd89dfbeca07ef27f3e5eb5d482354c4249

**Get the coordinates of the Public Key**

    
    $bitcoinECDSA->getPubKeyPoints();
    
Returns an array containing the x and y coordinates of the public key

Example :
Array ( [x] => a69243f3c4c047aba38d7ac3660317629c957ab1f89ea42343aee186538a34f8 [y] => b6d862f39819060378542a3bb43ff76b5d7bb23fc012f09c3cd2724bebe0b0bd ) 

**Get the Address**

    
    $bitcoinECDSA->getAddress();
    
Returns the compressed Bitcoin Address.

**Get the uncompressed Address**

    
    $bitcoinECDSA->getUncompressedAddress();
    
Returns the uncompressed Bitcoin Address.

