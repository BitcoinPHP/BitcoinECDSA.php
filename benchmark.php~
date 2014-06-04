<?php

set_time_limit(0);

use BitcoinPHP\BitcoinECDSA\BitcoinECDSA;

require_once("src/BitcoinPHP/BitcoinECDSA/BitcoinECDSA.php");

$bitcoinECDSA = new BitcoinECDSA();

$time = microtime(true);
for($i = 0; $i < 1000; $i++) {

	$bitcoinECDSA->generateRandomPrivateKey();
	$bitcoinECDSA->getAddress();

}
echo "generated 1000 Addresses in " . ((microtime(true)-$time)) ." seconds";

?>
