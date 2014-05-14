<?php
require_once("BitcoinECDSA.php");
$bitcoinECDSA = new BitcoinECDSA();

$k ="0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
$k ="00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC";


$bitcoinECDSA->setPrivateKey($k);

print_r($bitcoinECDSA->wif());

echo "<br/>";

print_r($bitcoinECDSA->generatePubKey());

echo "<br/>";

print_r($bitcoinECDSA->generateAddress());
?>
