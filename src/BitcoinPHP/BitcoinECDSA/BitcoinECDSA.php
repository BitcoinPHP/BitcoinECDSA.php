<?php

namespace BitcoinPHP\BitcoinECDSA;

if (!extension_loaded('gmp')) {
    throw new \Exception('GMP extension seems not to be installed');
}

class BitcoinECDSA
{

    public $k;
    public $a;
    public $b;
    public $p;
    public $n;
    public $G;

    public function __construct()
    {
        $this->a = gmp_init('0', 10);
        $this->b = gmp_init('7', 10);
        $this->p = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F', 16);
        $this->n = gmp_init('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141', 16);

        $this->G = array('x' => gmp_init('55066263022277343669578718895168534326250603453777594175500187360389116729240'),
                         'y' => gmp_init('32670510020758816978083085130507043184471273380659243275938904335757337482424'));

        $this->networkPrefix = '00';
    }

    /***
     * Set the network prefix, '00' = main network, '6f' = test network.
     *
     * @param String Hex $prefix
     */
    public function setNetworkPrefix($prefix)
    {
        $this->networkPrefix = $prefix;
    }

    /**
     * Returns the current network prefix, '00' = main network, '6f' = test network.
     *
     * @return String Hex
     */
    public function getNetworkPrefix()
    {
        return $this->networkPrefix;
    }

    /***
     * Permutation table used for Base58 encoding and decoding.
     *
     * @param $char
     * @param bool $reverse
     * @return null
     */
    public function base58_permutation($char, $reverse = false)
    {
        $table = array('1','2','3','4','5','6','7','8','9','A','B','C','D',
                       'E','F','G','H','J','K','L','M','N','P','Q','R','S','T','U','V','W',
                       'X','Y','Z','a','b','c','d','e','f','g','h','i','j','k','m','n','o',
                       'p','q','r','s','t','u','v','w','x','y','z'
                 );

        if($reverse)
        {
            $reversedTable = array();
            foreach($table as $key => $element)
            {
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

    /***
     * encode a hexadecimal string in Base58.
     *
     * @param String Hex $data
     * @param bool $littleEndian
     * @return String Base58
     * @throws \Exception
     */
    public function base58_encode($data, $littleEndian = true)
    {
        $res = '';
        $dataIntVal = gmp_init($data, 16);
        while(gmp_cmp($dataIntVal, gmp_init(0, 10)) > 0)
        {
            $qr = gmp_div_qr($dataIntVal, gmp_init(58, 10));
            $dataIntVal = $qr[0];
            $reminder = gmp_strval($qr[1]);
            if(!$this->base58_permutation($reminder))
            {
                throw new \Exception('Something went wrong during base58 encoding');
            }
            $res .= $this->base58_permutation($reminder);
        }

        //get number of leading zeros
        $leading = '';
        $i=0;
        while(substr($data, $i, 1) == '0')
        {
            if($i!= 0 && $i%2)
            {
                $leading .= '1';
            }
            $i++;
        }

        if($littleEndian)
            return strrev($res . $leading);
        else
            return $res.$leading;
    }

    /***
     * Decode a Base58 encoded string and returns it's value as a hexadecimal string
     *
     * @param $encodedData
     * @param bool $littleEndian
     * @return String Hex
     */
    public function base58_decode($encodedData, $littleEndian = true)
    {
        $res = gmp_init(0, 10);
        $length = strlen($encodedData);
        if($littleEndian)
        {
            $encodedData = strrev($encodedData);
        }

        for($i = $length - 1; $i >= 0; $i--)
        {
            $res = gmp_add(
                           gmp_mul(
                                   $res,
                                   gmp_init(58, 10)
                           ),
                           $this->base58_permutation(substr($encodedData, $i, 1), true)
                   );
        }

        $res = gmp_strval($res, 16);
        $i = $length - 1;
        while(substr($encodedData, $i, 1) == '1')
        {
            $res = '00' . $res;
            $i--;
        }

        if(strlen($res)%2 != 0)
        {
            $res = '0' . $res;
        }

        return $res;
    }

    /***
     * returns the private key under the Wallet Import Format
     *
     * @return String Base58
     * @throws \Exception
     */
    public function getWif()
    {
        if(!isset($this->k))
        {
            throw new \Exception('No Private Key was defined');
        }

        $k              = $this->k;
        $secretKey      = '80' . $k;
        $firstSha256    = hash('sha256', hex2bin($secretKey));
        $secondSha256   = hash('sha256', hex2bin($firstSha256));
        $secretKey     .= substr($secondSha256, 0, 8);

        return strrev($this->base58_encode($secretKey));
    }

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param Array $pt
     * @return Array Point
     * @throws \Exception
     */
    public function doublePoint(Array $pt)
    {
        $a = $this->a;
        $p = $this->p;

        $gcd = gmp_strval(gmp_gcd(gmp_mul(gmp_init(2, 10), $pt['y'] ), $p));
        if($gcd != '1')
        {
            throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
        }

        // SLOPE = (3 * ptX^2 + a )/( 2*ptY )
        // Equals (3 * ptX^2 + a ) * ( 2*ptY )^-1
        $slope = gmp_mod(
                         gmp_mul(
                                 gmp_invert(
                                            gmp_mul(
                                                    gmp_init(2, 10),
                                                    $pt['y']
                                            ),
                                            $p
                                 ),
                                 gmp_add(
                                         gmp_mul(
                                                 gmp_init(3, 10),
                                                 gmp_pow($pt['x'], 2)
                                         ),
                                         $a
                                 )
                         ),
                         $p
                );

        // nPtX = slope^2 - 2 * ptX
        // Equals slope^2 - ptX - ptX
        $nPt['x'] = gmp_mod(
                            gmp_sub(
                                    gmp_sub(
                                            gmp_pow($slope, 2),
                                            $pt['x']
                                    ),
                                    $pt['x']
                            ),
                            $p
                    );

        // nPtY = slope * (ptX - nPtx) - ptY
        $nPt['y'] = gmp_mod(
                            gmp_sub(
                                    gmp_mul(
                                            $slope,
                                            gmp_sub(
                                                    $pt['x'],
                                                    $nPt['x']
                                            )
                                    ),
                                    $pt['y']
                            ),
                            $p
                    );

        return $nPt;
    }

    /***
     * Computes the result of a point addition and returns the resulting point as an Array.
     *
     * @param Array $pt1
     * @param Array $pt2
     * @return Array Point
     * @throws \Exception
     */
    public function addPoints(Array $pt1, Array $pt2)
    {
        $p = $this->p;
        if(gmp_cmp($pt1['x'], $pt2['x']) == 0  && gmp_cmp($pt1['y'], $pt2['y']) == 0) //if identical
        {
            return $this->doublePoint($pt1);
        }

        $gcd = gmp_strval(gmp_gcd(gmp_sub($pt1['x'], $pt2['x']), $p));
        if($gcd != '1')
        {
            throw new \Exception('This library doesn\'t yet supports point at infinity.');
        }

        // SLOPE = (pt1Y - pt2Y)/( pt1X - pt2X )
        // Equals (pt1Y - pt2Y) * ( pt1X - pt2X )^-1
        $slope      = gmp_mod(
                              gmp_mul(
                                      gmp_sub(
                                              $pt1['y'],
                                              $pt2['y']
                                      ),
                                      gmp_invert(
                                                 gmp_sub(
                                                         $pt1['x'],
                                                         $pt2['x']
                                                 ),
                                                 $p
                                      )
                              ),
                              $p
                      );

        // nPtX = slope^2 - ptX1 - ptX2
        $nPt['x']   = gmp_mod(
                              gmp_sub(
                                      gmp_sub(
                                              gmp_pow($slope, 2),
                                              $pt1['x']
                                      ),
                                      $pt2['x']
                              ),
                              $p
                      );

        // nPtX = slope * (ptX1 - nPtX) - ptY1
        $nPt['y']   = gmp_mod(
                              gmp_sub(
                                      gmp_mul(
                                              $slope,
                                              gmp_sub(
                                                      $pt1['x'],
                                                      $nPt['x']
                                              )
                                      ),
                                      $pt1['y']
                              ),
                              $p
                      );

        return $nPt;
    }

    /***
     * Computes the result of a point multiplication and returns the resulting point as an Array.
     *
     * @param $k
     * @param Array $pG
     * @throws \Exception
     * @return Array Point
     */
    public function mulPoint($k, Array $pG)
    {
        //in order to calculate k*G
        $k = gmp_init($k);
        $kBin = gmp_strval($k, 2);

        $lastPoint = $pG;
        for($i = 1; $i < strlen($kBin); $i++)
        {
            if(substr($kBin, $i, 1) == 1 )
            {
                $dPt = $this->doublePoint($lastPoint);
                $lastPoint = $this->addPoints($dPt, $pG);
            }
            else
            {
                $lastPoint = $this->doublePoint($lastPoint);
            }
        }
        if(!$this->validatePoint(gmp_strval($lastPoint['x'], 16), gmp_strval($lastPoint['y'], 16)))
            throw new \Exception('The resulting point is not on the curve.');
        return $lastPoint;
    }

    /***
     * Calculates the square root of $a mod p and returns the 2 solutions as an array.
     *
     * @param $a
     * @return array|null
     * @throws \Exception
     */
    public function sqrt($a)
    {
        $p = $this->p;

        if(gmp_legendre($a, $p) != 1)
        {
            //no result
            return null;
        }

        if(gmp_strval(gmp_mod($p, gmp_init(4, 10)), 10) == 3)
        {
            $sqrt1 = gmp_powm(
                            $a,
                            gmp_div_q(
                                gmp_add($p, gmp_init(1, 10)),
                                gmp_init(4, 10)
                            ),
                            $p
                    );
            // there are always 2 results for a square root
            // In an infinite number field you have -2^2 = 2^2 = 4
            // In a finite number field you have a^2 = (p-a)^2
            $sqrt2 = gmp_mod(gmp_sub($p, $sqrt1), $p);
            return array($sqrt1, $sqrt2);
        }
        else
        {
            throw new \Exception('P % 4 != 3 , this isn\'t supported yet.');
        }
    }

    /***
     * Calculate the Y coordinates for a given X coordinate.
     *
     * @param $x
     * @param null $derEvenOrOddCode
     * @return array|null|String
     */
    public function calculateYWithX($x, $derEvenOrOddCode = null)
    {
        $a  = $this->a;
        $b  = $this->b;
        $p  = $this->p;

        $x  = gmp_init($x, 16);
        $y2 = gmp_mod(
                      gmp_add(
                              gmp_add(
                                      gmp_powm($x, gmp_init(3, 10), $p),
                                      gmp_mul($a, $x)
                              ),
                              $b
                      ),
                      $p
              );

        $y = $this->sqrt($y2);
        if(!$derEvenOrOddCode)
        {
            return $y;
        }
        else if($derEvenOrOddCode == '02') // even
        {
            $resY = null;
            if(!gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[0], 16);
            if(!gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[1], 16);
            if($resY)
            {
                while(strlen($resY) < 64)
                {
                    $resY = '0' . $resY;
                }

            }
            return $resY;
        }
        else if($derEvenOrOddCode == '03') // odd
        {
            $resY = null;
            if(gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[0], 16);
            if(gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[1], 16);
            if($resY)
            {
                while(strlen($resY) < 64)
                {
                    $resY = '0' . $resY;
                }

            }
            return $resY;
        }

        return null;
    }


    public function getPubKeyPointsWithDerPubKey($derPubKey)
    {
        if(substr($derPubKey, 0, 2) == '04' && strlen($derPubKey) == 130)
        {
            //uncompressed der encoded public key
            $x = substr($derPubKey, 2, 64);
            $y = substr($derPubKey, 66, 64);
            return array('x' => $x, 'y' => $y);
        }
        else if((substr($derPubKey, 0, 2) == '02' || substr($derPubKey, 0, 2) == '03') && strlen($derPubKey) == 66)
        {
            //compressed der encoded public key
            $x = substr($derPubKey, 2, 64);
            $y = $this->calculateYWithX($x, substr($derPubKey, 0, 2));
            return array('x' => $x, 'y' => $y);
        }
        else
        {
            throw new \Exception('Invalid derPubKey format : ' . $derPubKey);
        }
    }

    /***
     * Returns true if the point is on the curve and false if it isn't.
     *
     * @param $x
     * @param $y
     * @return bool
     */
    public function validatePoint($x, $y)
    {
        $a  = $this->a;
        $b  = $this->b;
        $p  = $this->p;

        $x  = gmp_init($x, 16);
        $y2 = gmp_mod(
            gmp_add(
                gmp_add(
                    gmp_powm($x, gmp_init(3, 10), $p),
                    gmp_mul($a, $x)
                ),
                $b
            ),
            $p
        );
        $y = gmp_mod(gmp_pow(gmp_init($y, 16), 2), $p);

        if(gmp_cmp($y2, $y) == 0)
            return true;
        else
            return false;
    }

    /***
     * returns the X and Y point coordinates of the public key.
     *
     * @return Array Point
     * @throws \Exception
     */
    public function getPubKeyPoints()
    {
        $a = $this->a;
        $b = $this->b;
        $p = $this->p;
        $G = $this->G;
        $k = $this->k;

        if(!isset($this->k))
        {
            throw new \Exception('No Private Key was defined');
        }

        $pubKey 	    = $this->mulPoint(gmp_strval(gmp_init($k, 16)),
                                          array('x'=>$G['x'], 'y'=>$G['y']),
                                          $a,
                                          $b,
                                          $p
                                  );

        $pubKey['x']	= gmp_strval($pubKey['x'], 16);
        $pubKey['y']	= gmp_strval($pubKey['y'], 16);

        while(strlen($pubKey['x']) < 64)
        {
            $pubKey['x'] = '0' . $pubKey['x'];
        }

        while(strlen($pubKey['y']) < 64)
        {
            $pubKey['y'] = '0' . $pubKey['y'];
        }

        return $pubKey;
    }

    /***
     * returns the uncompressed DER encoded public key.
     *
     * @return String Hex
     */
    public function getUncompressedPubKey()
    {
        $pubKey			    = $this->getPubKeyPoints();
        $uncompressedPubKey	= '04' . $pubKey['x'] . $pubKey['y'];

        return $uncompressedPubKey;
    }

    /***
     * returns the compressed DER encoded public key.
     *
     * @return String Hex
     */
    public function getPubKey()
    {
        $pubKey = $this->getPubKeyPoints();

        if(gmp_strval(gmp_mod(gmp_init($pubKey['y'], 16), gmp_init(2, 10))) == 0)
            $pubKey  	= '02' . $pubKey['x'];	//if $pubKey['y'] is even
        else
            $pubKey  	= '03' . $pubKey['x'];	//if $pubKey['y'] is odd

        return $pubKey;
    }

    /***
     * returns the uncompressed Bitcoin address generated from the private key if $compressed is false and
     * the compressed if $compressed is true.
     *
     * @param bool $compressed
     * @throws \Exception
     * @return String Base58
     */
    public function getUncompressedAddress($compressed = false)
    {
        if($compressed) {
            $address 	= $this->getPubKey();
        }
        else {
            $address 	= $this->getUncompressedPubKey();
        }

        $sha256		    = hash('sha256', hex2bin($address));
        $ripem160 	    = hash('ripemd160', hex2bin($sha256));
        $address 	    = $this->getNetworkPrefix() . $ripem160;

        //checksum
        $sha256		    = hash('sha256', hex2bin($address));
        $sha256		    = hash('sha256', hex2bin($sha256));
        $address 	    = $address.substr($sha256, 0, 8);
        $address        = $this->base58_encode($address);

        if($this->validateAddress($address))
            return $address;
        else
            throw new \Exception('the generated address seems not to be valid.');
    }

    /***
     * returns the compressed Bitcoin address generated from the private key.
     *
     * @return String Base58
     */
    public function getAddress()
    {
        return $this->getUncompressedAddress(true);
    }

    /***
     * set a private key.
     *
     * @param String Hex $k
     * @throws \Exception
     */
    public function setPrivateKey($k)
    {
        //private key has to be passed as an hexadecimal number
        if(gmp_cmp(gmp_init($k, 16), gmp_sub($this->n, gmp_init(1, 10))) == 1)
        {
            throw new \Exception('Private Key is not in the 1,n-1 range');
        }
        $this->k = $k;
    }

    /***
     * return the private key.
     *
     * @return String Hex
     */
    public function getPrivateKey()
    {
        return $this->k;
    }


    /***
     * Generate a new random private key.
     * The extra parameter can be some random data typed down by the user or mouse movements to add randomness.
     *
     * @param string $extra
     * @throws \Exception
     */
    public function generateRandomPrivateKey($extra = 'FSQF5356dsdsqdfEFEQ3fq4q6dq4s5d')
    {
        //private key has to be passed as an hexadecimal number
        do { //generate a new random private key until to find one that is valid
            $bytes      = openssl_random_pseudo_bytes(256, $cStrong);
            $hex        = bin2hex($bytes);
            $random     = $hex . microtime(true).rand(100000000000, 1000000000000) . $extra;
            $this->k    = hash('sha256', $random);

            if(!$cStrong)
            {
                throw new \Exception('Your system is not able to generate strong enough random numbers');
            }

        } while(gmp_cmp(gmp_init($this->k, 16), gmp_sub($this->n, gmp_init(1, 10))) == 1);
    }

    /***
     * Tests if the address is valid or not.
     *
     * @param String Base58 $address
     * @return bool
     */
    public function validateAddress($address)
    {
        $address    = hex2bin($this->base58_decode($address));
        if(strlen($address) != 25)
            return false;
        $checksum   = substr($address, 21, 4);
        $rawAddress = substr($address, 0, 21);
        $sha256		= hash('sha256', $rawAddress);
        $sha256		= hash('sha256', hex2bin($sha256));

        if(substr(hex2bin($sha256), 0, 4) == $checksum)
            return true;
        else
            return false;
    }

    /***
     * Tests if the Wif key (Wallet Import Format) is valid or not.
     *
     * @param String Base58 $wif
     * @return bool
     */
    public function validateWifKey($wif)
    {
        $key            = $this->base58_decode($wif, false);
        $length         = strlen($key);
        $firstSha256    = hash('sha256', hex2bin(substr($key, 0, $length - 8)));
        $secondSha256   = hash('sha256', hex2bin($firstSha256));
        if(substr($secondSha256, 0, 8) == substr($key, $length - 8, 8))
            return true;
        else
            return false;
    }
}

?>
