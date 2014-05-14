<?php
require_once("BitcoinECDSA.php");
$bitcoinECDSA = new BitcoinECDSA();

$k ="0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
$k ="00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC";
$k ="f2831dbca97e8fda6ffe2cd3d0c1c0296b23f9f115d8d7cbf4c94e3da4f6e3bb";

$bitcoinECDSA->setPrivateKey($k);

//$bitcoinECDSA->generateRandomPrivateKey();

print_r($bitcoinECDSA->getPrivateKey());

echo "<br/>";

print_r($bitcoinECDSA->wif());

echo "<br/>";

print_r($bitcoinECDSA->generatePubKey());

echo "<br/>";

print_r($bitcoinECDSA->generateAddress());
?>
