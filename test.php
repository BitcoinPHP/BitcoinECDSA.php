<?php
require_once("BitcoinECDSA.php");
$bitcoinECDSA = new BitcoinECDSA();

$k ="0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
$k ="00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC";

print_r($bitcoinECDSA->wif($k));

echo "<br/>";

$pubKey = $bitcoinECDSA->generatePubKey($k);
print_r($pubKey);

echo "<br/>";

print_r($bitcoinECDSA->generateAddress($pubKey));
?>
