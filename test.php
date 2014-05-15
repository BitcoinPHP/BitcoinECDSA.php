<?php
set_time_limit(0);

require_once("BitcoinECDSA.php");
$bitcoinECDSA = new BitcoinECDSA();

$k ="0C28FCA386C7A227600B2FE50B7CAE11EC86D3BF1FBE471BE89827E19D72AA1D";
$k ="00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC";
$k ="f2831dbca97e8fda6ffe2cd3d0c1c0296b23f9f115d8d7cbf4c94e3da4f6e3bb";

$bitcoinECDSA->setPrivateKey($k);



for($i = 0; $i<20; $i++) {

	$filename = "private".time().rand(1000000,100000000000).".key";
	$fp = fopen($filename,"w+");

	$bitcoinECDSA->generateRandomPrivateKey();

	$bitcoinECDSA->setPrivateKey('4e5be7d3cd7685eb456e45a3c27352623bcf82fa195e77482a2297425e36e7cf');

	fwrite($fp,$bitcoinECDSA->getPrivateKey());

	//now using the SX tool check if the generated address match with the address that is generated with SX
	//echo exec("cat private.key | sx addr")."<br/>";
	//echo "<b>".$bitcoinECDSA->getAddress()."</b><br/>";

	$sxPubKey = exec("cat $filename | sx pubkey");

	if($bitcoinECDSA->getPubKey() != $sxPubKey) {
		throw new Exception('Something went wrong for privateKey : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');
	}

	$sxAddr =  exec("cat $filename | sx addr");
echo "<i>".$sxAddr."</i><br/>";
echo "<b>".$bitcoinECDSA->getAddress()."</b><br/>";
	if($bitcoinECDSA->getAddress() != $sxAddr) {
		throw new Exception('Something went wrong for privateKey : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');
	}
	unlink($filename);
}

echo "Tests ended successfully";

/*
print_r($bitcoinECDSA->getPrivateKey());

echo "<br/>";

print_r($bitcoinECDSA->getWif());

echo "<br/>";

print_r($bitcoinECDSA->getPubKey());

echo "<br/>";

print_r($bitcoinECDSA->getAddress());
*/
?>
