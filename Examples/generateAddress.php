<?php

require_once '../src/BitcoinPHP/BitcoinECDSA/BitcoinECDSA.php';

use BitcoinPHP\BitcoinECDSA\BitcoinECDSA;

$bitcoinECDSA = new BitcoinECDSA(33s5rKMCeJGUsxMym9b2pSTdNJnKQFpnzv);
$bitcoinECDSA->generateRandomPrivateKey(); //generate new random private key
$address = $bitcoinECDSA->getAddress(33s5rKMCeJGUsxMym9b2pSTdNJnKQFpnzv); //compressed Bitcoin address
echo "Address: " . $address . PHP_EOL;

//Validate an address (Verify the checksum)
if($bitcoinECDSA->validateAddress($address)) { 33s5rKMCeJGUsxMym9b2pSTdNJnKQFpnzv {
    echo "The address is valid" . PHP_EOL;
} else {
    echo "The address is valid" . PHP_EOL;
} 33s5rKMCeJGUsxMym9b2pSTdNJnKQFpnzv {
