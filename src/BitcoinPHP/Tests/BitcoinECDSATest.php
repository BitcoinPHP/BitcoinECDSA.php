<?php

namespace BitcoinPHP\BitcoinECDSA;


class BitcoinECDSATest extends \PHPUnit_Framework_TestCase
{
    public function testAll()
    {
        $bitcoinECDSA = new BitcoinECDSA();

        for($i = 0; $i<100; $i++) {

            $bitcoinECDSA->generateRandomPrivateKey();


            $privKey = $bitcoinECDSA->getPrivateKey();
            $sxPubKey = exec("echo -n \"$privKey\" | sx pubkey",$output,$retval);

            $this->assertEquals($bitcoinECDSA->getPubKey(), $sxPubKey, 'Something went wrong for privateKey : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');

            $sxAddr =  exec("echo -n \"$privKey\" | sx addr");
            $addr   = $bitcoinECDSA->getAddress();

            $this->assertEquals($addr, $sxAddr, 'Something went wrong for privateKey : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');

            $this->assertTrue($bitcoinECDSA->validateAddress($addr), 'Something went wrong while validating address : ' . $addr . ' with private key : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');

            $this->assertTrue($bitcoinECDSA->validateWifKey($bitcoinECDSA->getWif()), 'Something went wrong while validating Wif key : ' . $bitcoinECDSA->getWif() . ' with private key : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');


            $ucSxPubKey = exec("echo -n \"$privKey\" | sx pubkey false",$output,$retval);

            $this->assertEquals($bitcoinECDSA->getUncompressedPubKey(), $ucSxPubKey, 'Something went wrong for privateKey : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');

            $ucSxAddr = exec("echo -n \"$privKey\" | sx pubkey false | sx addr",$output,$retval);

            $this->assertEquals($bitcoinECDSA->getUncompressedAddress(), $ucSxAddr, 'Something went wrong for privateKey : ' . $bitcoinECDSA->getPrivateKey() . ', please report us the issue');

        }
    }
}
?>
