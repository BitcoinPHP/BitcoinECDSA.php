<?php

namespace BitcoinPHP\BitcoinECDSA;

if (!extension_loaded('gmp')) {
    throw new Exception('GMP extension seems not to be installed');
}

class BitcoinECDSA {

    public function __construct() {
        $this->a = gmp_init("0");
        $this->b = gmp_init("7");
        $this->p = gmp_init("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F",16);
        $this->n = gmp_init("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",16);

        $this->G = array('x' => gmp_init("55066263022277343669578718895168534326250603453777594175500187360389116729240"),
            'y' => gmp_init("32670510020758816978083085130507043184471273380659243275938904335757337482424"));
    }

    public function base58_permutation($char, $reverse = false) {
        $table = array("1","2","3","4","5","6","7","8","9","A","B","C","D",
            "E","F","G","H","J","K","L","M","N","P","Q","R","S","T","U","V","W",
            "X","Y","Z","a","b","c","d","e","f","g","h","i","j","k","m","n","o",
            "p","q","r","s","t","u","v","w","x","y","z");

        if($reverse) {
            $reversedTable = array();
            foreach($table as $key => $element) {
                $reversedTable[$element] = $key;
            }
            if(isset($reversedTable[$char]))
                return $reversedTable[$char];
            else
                return null;
        }
        if(isset($table[$char]))
            return $table[$char];
        else
            return null;
    }

    public function base58_encode($data, $littleEndian = true) {
        $res = "";
        $dataIntVal = gmp_init($data, 16);
        while(gmp_cmp($dataIntVal, "0") > 0)
        {
            $qr = gmp_div_qr($dataIntVal, 58);
            $dataIntVal = $qr[0];
            $reminder = gmp_strval($qr[1]);
            if(!$this->base58_permutation($reminder))
            {
                throw new Exception('Something went wrong during base58 encoding');
            }
            $res .= $this->base58_permutation($reminder);
        }

        //get number of leading zeros
        $leading = '';
        $i=0;
        while(substr($data, $i, 1) == '0')
        {
            if($i!= 0 && $i%2)
                $leading .= '1';
            $i++;
        }

        if($littleEndian)
            return strrev($res.$leading);
        else
            return $res.$leading;
    }

    public function base58_decode($encodedData, $littleEndian = true) {
        $res = gmp_init("0");
        $length = strlen($encodedData);
        if($littleEndian)
            $encodedData = strrev($encodedData);
        for($i = $length - 1; $i >= 0; $i--)
        {
            $res = gmp_add(gmp_mul($res, 58), $this->base58_permutation(substr($encodedData, $i, 1), true));
        }

        $res = gmp_strval($res, 16);
        $i = $length - 1;
        while(substr($encodedData, $i, 1) == "1") {
            $res = "00".$res;
            $i--;
        }
        if(strlen($res)%2 != 0)
            $res = "0".$res;
        return $res;
    }

    //Wallet Import Format
    public function getWif() {

        if(!isset($this->k))
        {
            throw new Exception('No Private Key was defined');
        }
        $k              = $this->k;
        $secretKey      = "80".$k;
        $firstSha256    = hash("sha256", hex2bin($secretKey));
        $secondSha256   = hash("sha256", hex2bin($firstSha256));
        $secretKey     .= substr($secondSha256, 0, 8);
        return strrev($this->base58_encode($secretKey));
    }

    public function doublePoint($pt) {

        $a = $this->a;
        $p = $this->p;

        // SLOPE = (3 * ptX^2 + a )/( 2*ptY )

        $gcd = gmp_strval(gmp_gcd(gmp_mul(2, $pt['y'] ), $p));
        if($gcd!="1")
        {
            throw new Exception('GCD is not equal to 1, Something went wrong in the public key generation');
        }

        $s = gmp_mod(gmp_mul(gmp_invert(gmp_mul(2, $pt['y'] ), $p), gmp_add(gmp_mul(3, gmp_pow($pt['x'], 2)), $a)), $p);

        $nPt['x'] = gmp_mod(gmp_sub(gmp_sub(gmp_pow($s, 2), $pt['x']), $pt['x']), $p);
        $nPt['y'] = gmp_mod(gmp_sub(gmp_mul($s, gmp_sub($pt['x'], $nPt['x'])), $pt['y']), $p);

        return $nPt;
    }

    public function addPoints($pt1, $pt2) {

        $p = $this->p;

        if(gmp_cmp($pt1['x'], $pt2['x']) == 0  && gmp_cmp($pt1['y'], $pt2['y']) == 0) //if identical
            return $this->doublePoint($pt1);

        // SLOPE = (pt1Y - pt2Y)/( pt1X - pt2X )
        // <=> (pt1Y - pt2Y) * ( pt1X - pt2X )^-1

        $gcd = gmp_strval(gmp_gcd(gmp_sub($pt1['x'], $pt2['x']), $p));
        if($gcd!="1")
        {
            throw new Exception('GCD is not equal to 1, Something went wrong in the public key generation');
        }

        $s = gmp_mod(gmp_mul(gmp_sub($pt1['y'], $pt2['y']), gmp_invert(gmp_sub($pt1['x'], $pt2['x']), $p)), $p);

        $nPt['x'] = gmp_mod(gmp_sub(gmp_sub(gmp_pow($s, 2), $pt1['x']), $pt2['x']),$p);
        $nPt['y'] = gmp_mod(gmp_sub(gmp_mul($s, gmp_sub($pt1['x'], $nPt['x'])), $pt1['y']), $p);

        return $nPt;
    }

    public function mulPoint($k, $pG) {
        //in order to calculate k*G
        $k = gmp_init($k);
        $kBin = gmp_strval($k, 2);

        $lastPoint = $pG;
        for($i = 1; $i < strlen($kBin); $i++) {

            if(substr($kBin, $i, 1) == 1 ) {
                $dPt = $this->doublePoint($lastPoint);
                $lastPoint = $this->addPoints($dPt, $pG);
            }
            else {
                $lastPoint = $this->doublePoint($lastPoint);
            }

        }
        return $lastPoint;
    }

    public function getPubKeyPoints() {

        $a = $this->a;
        $b = $this->b;
        $p = $this->p;
        $G = $this->G;

        if(!isset($this->k))
        {
            throw new Exception('No Private Key was defined');
        }
        $k = $this->k;

        $pubKey 	    = $this->mulPoint(gmp_strval(gmp_init($k, 16)), array('x'=>$G['x'], 'y'=>$G['y']), $a, $b, $p);
        $pubKey['x']	= gmp_strval($pubKey['x'], 16);
        $pubKey['y']	= gmp_strval($pubKey['y'], 16);
        while(strlen($pubKey['x']) < 64) {
            $pubKey['x'] = '0'.$pubKey['x'];
        }
        while(strlen($pubKey['y']) < 64) {
            $pubKey['y'] = '0'.$pubKey['y'];
        }
        return $pubKey;
    }

    public function getUncompressedPubKey() {

        $pubKey			= $this->getPubKeyPoints();
        $uncompressedPubKey	= "04".$pubKey['x'].$pubKey['y'];
        return $uncompressedPubKey;
    }

    public function getPubKey() {

        $pubKey = $this->getPubKeyPoints();
        if(gmp_strval(gmp_mod(gmp_init($pubKey['y'], 16), 2)) == 0)
            $pubKey  	= "02".$pubKey['x'];	//if $pubKey['y'] is even
        else
            $pubKey  	= "03".$pubKey['x'];	//if $pubKey['y'] is odd

        return $pubKey;
    }

    public function getUncompressedAddress($compressed = false) {

        if($compressed) {
            $address 	= $this->getPubKey();
        }
        else {
            $address 	= $this->getUncompressedPubKey();
        }

        $sha256		= hash("sha256", hex2bin($address));
        $ripem160 	= hash("ripemd160", hex2bin($sha256));
        $address 	= "00".$ripem160; //00 = main network, 6f = test network

        //checksum
        $sha256		= hash("sha256", hex2bin($address));
        $sha256		= hash("sha256", hex2bin($sha256));
        $address 	= $address.substr($sha256, 0, 8);

        return $this->base58_encode($address);
    }

    public function getAddress() {
        return $this->getUncompressedAddress(true);
    }

    public function setPrivateKey($k) {
        //private key has to be passed as an hexadecimal number
        if(gmp_cmp(gmp_init($k, 16), gmp_sub($this->n, 1)) == 1)
        {
            throw new Exception('Private Key is not in the 1,n-1 range');
        }
        $this->k = $k;
    }

    public function getPrivateKey() {
        return $this->k;
    }

    //extra parameter can be some random data typed down by the user or mouse movements to add randomness
    public function generateRandomPrivateKey($extra = 'FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d') {
        //private key has to be passed as an hexadecimal number
        do { //generate a new random private key until to find one that is valid
            $bytes      = openssl_random_pseudo_bytes(128, $cstrong);
            $hex        = bin2hex($bytes);
            $random     = $hex . microtime(true).rand(100000000000, 1000000000000).$extra;
            $this->k    = hash('sha256', $random);

            if(!$cstrong) {
                throw new Exception('Your system is not able to generate strong enough random numbers');
            }

        } while(gmp_cmp(gmp_init($this->k, 16), gmp_sub($this->n, 1)) == 1);
    }

    /***
     * Tests if the address is valid or not.
     *
     * @param {Base58} $address
     * @return bool
     */
    public function validateAddress($address) {

        $address    = hex2bin($this->base58_decode($address));
        if(strlen($address) != 25)
            return false;
        $checksum   = substr($address, 21, 4);
        $rawAddress = substr($address, 0, 21);
        $sha256		= hash("sha256", $rawAddress);
        $sha256		= hash("sha256", hex2bin($sha256));

        if(substr(hex2bin($sha256), 0, 4) == $checksum)
            return true;
        else
            return false;
    }

    /***
     * Tests if the Wif key (Wallet Import Format) is valid or not.
     *
     * @param {Base58} $wif
     * @return bool
     */
    public function validateWifKey($wif) {

        $key        = $this->base58_decode($wif, false);
        $length     = strlen($key);
        $firstSha256    = hash("sha256", hex2bin(substr($key, 0, $length - 8)));
        $secondSha256   = hash("sha256", hex2bin($firstSha256));
        if(substr($secondSha256, 0, 8) == substr($key, $length - 8, 8))
            return true;
        else
            return false;
    }
}

?>
