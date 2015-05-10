<?php

/**
 *
 * @author Jan Moritz Lindemann
 */

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
    public $networkPrefix;

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
     * Convert a number to a compact Int
     * taken from https://github.com/scintill/php-bitcoin-signature-routines/blob/master/verifymessage.php
     *
     * @param $i
     * @return string
     * @throws \Exception
     */
    public function numToVarIntString($i) {
        if ($i < 0xfd) {
            return chr($i);
        } else if ($i <= 0xffff) {
            return pack('Cv', 0xfd, $i);
        } else if ($i <= 0xffffffff) {
            return pack('CV', 0xfe, $i);
        } else {
            throw new \Exception('int too large');
        }
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
     * Bitcoin standard 256 bit hash function : double sha256
     *
     * @param $data
     * @return string
     */
    public function hash256($data)
    {
        return hash('sha256', hex2bin(hash('sha256', $data)));
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

        $gcd = gmp_strval(gmp_gcd(gmp_mod(gmp_mul(gmp_init(2, 10), $pt['y']), $p),$p));
        if($gcd != '1')
        {
            throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
        }

        // SLOPE = (3 * ptX^2 + a )/( 2*ptY )
        // Equals (3 * ptX^2 + a ) * ( 2*ptY )^-1
        $slope = gmp_mod(
                         gmp_mul(
                                 gmp_invert(
                                            gmp_mod(
                                                    gmp_mul(
                                                            gmp_init(2, 10),
                                                            $pt['y']
                                                    ),
                                                    $p
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
        $nPt = array();
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
            throw new \Exception('This library doesn\'t yet supports point at infinity. See https://github.com/BitcoinPHP/BitcoinECDSA.php/issues/9');
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
        $nPt = array();
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
     * @param String Hex $k
     * @param Array $pG
     * @param $base
     * @throws \Exception
     * @return Array Point
     */
    public function mulPoint($k, Array $pG, $base = null)
    {
        //in order to calculate k*G
        if($base == 16 || $base == null || is_resource($base))
            $k = gmp_init($k, 16);
        if($base == 10)
            $k = gmp_init($k, 10);
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

        if(!$y) //if there is no result
        {
            return null;
        }

        if(!$derEvenOrOddCode)
        {
            return $y;
        }

        else if($derEvenOrOddCode == '02') // even
        {
            $resY = null;
            if(false == gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[0], 16);
            if(false == gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10))
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
            if(true == gmp_strval(gmp_mod($y[0], gmp_init(2, 10)), 10))
                $resY = gmp_strval($y[0], 16);
            if(true == gmp_strval(gmp_mod($y[1], gmp_init(2, 10)), 10))
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

    /***
     * returns the public key coordinates as an array.
     *
     * @param $derPubKey
     * @return array
     * @throws \Exception
     */
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


    public function getDerPubKeyWithPubKeyPoints($pubKey, $compressed = true)
    {
        if(true != $compressed)
        {
            return '04' . $pubKey['x'] . $pubKey['y'];
        }
        else
        {
            if(gmp_strval(gmp_mod(gmp_init($pubKey['y'], 16), gmp_init(2, 10))) == 0)
                $pubKey  	= '02' . $pubKey['x'];	//if $pubKey['y'] is even
            else
                $pubKey  	= '03' . $pubKey['x'];	//if $pubKey['y'] is odd

            return $pubKey;
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
        $G = $this->G;
        $k = $this->k;

        if(!isset($this->k))
        {
            throw new \Exception('No Private Key was defined');
        }

        $pubKey 	    = $this->mulPoint($k,
                                          array('x' => $G['x'], 'y' => $G['y'])
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
     * @param string $derPubKey
     * @throws \Exception
     * @return String Base58
     */
    public function getUncompressedAddress($compressed = false, $derPubKey = null)
    {
        if(null != $derPubKey)
        {
            $address = $derPubKey;
        }
        else
        {
            if($compressed) {
                $address 	= $this->getPubKey();
            }
            else {
                $address 	= $this->getUncompressedPubKey();
            }
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
     * @param string $derPubKey
     * @return String Base58
     */
    public function getAddress($derPubKey = null)
    {
        return $this->getUncompressedAddress(true, $derPubKey);
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

    /***
     * Sign a hash with the private key that was set and returns signatures as an array (R,S)
     *
     * @param $hash
     * @param null $nonce
     * @throws \Exception
     * @return Array
     */
    public function getSignatureHashPoints($hash, $nonce = null)
    {
        $n = $this->n;
        $k = $this->k;

        if(empty($k))
        {
            throw new \Exception('No Private Key was defined');
        }

        if(null == $nonce)
        {
            $random     = openssl_random_pseudo_bytes(256, $cStrong);
            $random     = $random . microtime(true).rand(100000000000, 1000000000000);
            $nonce      = gmp_strval(gmp_mod(gmp_init(hash('sha256',$random), 16), $n), 16);
        }

        //first part of the signature (R).

        $rPt = $this->mulPoint($nonce, $this->G);
        $R	= gmp_strval($rPt ['x'], 16);

        while(strlen($R) < 64)
        {
            $R = '0' . $R;
        }

        //second part of the signature (S).
        //S = nonce^-1 (hash + privKey * R) mod p

        $S = gmp_strval(
                        gmp_mod(
                                gmp_mul(
                                        gmp_invert(
                                                   gmp_init($nonce, 16),
                                                   $n
                                        ),
                                        gmp_add(
                                                gmp_init($hash, 16),
                                                gmp_mul(
                                                        gmp_init($k, 16),
                                                        gmp_init($R, 16)
                                                )
                                        )
                                ),
                                $n
                        ),
                        16
             );

        if(strlen($S)%2)
        {
            $S = '0' . $S;
        }

        if(strlen($R)%2)
        {
            $R = '0' . $R;
        }

        return array('R' => $R, 'S' => $S);
    }

    /***
     * Sign a hash with the private key that was set and returns a DER encoded signature
     *
     * @param $hash
     * @param null $nonce
     * @return string
     */
    public function signHash($hash, $nonce = null)
    {
        $points = $this->getSignatureHashPoints($hash, $nonce);

        $signature = '02' . dechex(strlen(hex2bin($points['R']))) . $points['R'] . '02' . dechex(strlen(hex2bin($points['S']))) . $points['S'];
        $signature = '30' . dechex(strlen(hex2bin($signature))) . $signature;

        return $signature;
    }

    /***
     * Satoshi client's standard message signature implementation.
     *
     * @param $message
     * @param bool $compressed
     * @param null $nonce
     * @return string
     * @throws \Exception
     */
    public function signMessage($message, $compressed = true, $nonce = null)
    {

        $hash = $this->hash256("\x18Bitcoin Signed Message:\n" . $this->numToVarIntString(strlen($message)). $message);
        $points = $this->getSignatureHashPoints(
                                                $hash,
                                                $nonce
                   );

        $R = $points['R'];
        $S = $points['S'];

        while(strlen($R) < 64)
            $R = '0' . $R;

        while(strlen($S) < 64)
            $S = '0' . $S;

        $res = "\n-----BEGIN BITCOIN SIGNED MESSAGE-----\n";
        $res .= $message;
        $res .= "\n-----BEGIN SIGNATURE-----\n";
        if(true == $compressed)
            $res .= $this->getAddress() . "\n";
        else
            $res .= $this->getUncompressedAddress() . "\n";

        $finalFlag = 0;
        for($i = 0; $i < 4; $i++)
        {
            $flag = 27;
            if(true == $compressed)
                $flag += 4;
            $flag += $i;

            $pubKeyPts = $this->getPubKeyPoints();
            //echo "\nReal pubKey : \n";
            //print_r($pubKeyPts);

            $recoveredPubKey = $this->getPubKeyWithRS($flag, $R, $S, $hash);
            //echo "\nRecovered PubKey : \n";
            //print_r($recoveredPubKey);

            if($this->getDerPubKeyWithPubKeyPoints($pubKeyPts, $compressed) == $recoveredPubKey)
            {
                $finalFlag = $flag;
            }
        }

        //echo "Final flag : " . dechex($finalFlag) . "\n";
        if(0 == $finalFlag)
        {
            throw new \Exception('Unable to get a valid signature flag.');
        }


        $res .= base64_encode(hex2bin(dechex($finalFlag) . $R . $S));
        $res .= "\n-----END BITCOIN SIGNED MESSAGE-----";

        return $res;
    }

    /***
     * extract the public key from the signature and using the recovery flag.
     * see http://crypto.stackexchange.com/a/18106/10927
     * based on https://github.com/brainwallet/brainwallet.github.io/blob/master/js/bitcoinsig.js
     * possible public keys are r−1(sR−zG) and r−1(sR′−zG)
     * Recovery flag rules are :
     * binary number between 28 and 35 inclusive
     * if the flag is > 30 then the address is compressed.
     *
     * @param $flag
     * @param $R
     * @param $S
     * @param $hash
     * @return array
     */
    public function getPubKeyWithRS($flag, $R, $S, $hash)
    {

        $isCompressed = false;

        if ($flag < 27 || $flag >= 35)
            return false;

        if($flag >= 31) //if address is compressed
        {
            $isCompressed = true;
            $flag -= 4;
        }

        $recid = $flag - 27;

        //step 1.1
        $x = null;
        $x = gmp_add(
                     gmp_init($R, 16),
                     gmp_mul(
                             $this->n,
                             gmp_div_q( //check if j is equal to 0 or to 1.
                                        gmp_init($recid, 10),
                                        gmp_init(2, 10)
                             )
                     )
             );

        //step 1.3
        $y = null;
        if(1 == $flag % 2) //check if y is even.
        {
            $gmpY = $this->calculateYWithX(gmp_strval($x, 16), '02');
            if(null != $gmpY)
                $y = gmp_init($gmpY, 16);
        }
        else
        {
            $gmpY = $this->calculateYWithX(gmp_strval($x, 16), '03');
            if(null != $gmpY)
                $y = gmp_init($gmpY, 16);
        }

        if(null == $y)
            return null;

        $Rpt = array('x' => $x, 'y' => $y);

        //step 1.6.1
        //calculate r^-1 (S*Rpt - eG)

        $eG = $this->mulPoint($hash, $this->G);

        $eG['y'] = gmp_mod(gmp_neg($eG['y']), $this->p);

        $SR = $this->mulPoint($S, $Rpt);

        $pubKey = $this->mulPoint(
                            gmp_strval(gmp_invert(gmp_init($R, 16), $this->n), 16),
                            $this->addPoints(
                                             $SR,
                                             $eG
                            )
                  );

        $pubKey['x'] = gmp_strval($pubKey['x'], 16);
        $pubKey['y'] = gmp_strval($pubKey['y'], 16);

        while(strlen($pubKey['x']) < 64)
            $pubKey['x'] = '0' . $pubKey['x'];

        while(strlen($pubKey['y']) < 64)
            $pubKey['y'] = '0' . $pubKey['y'];

        $derPubKey = $this->getDerPubKeyWithPubKeyPoints($pubKey, $isCompressed);


        if($this->checkSignaturePoints($derPubKey, $R, $S, $hash))
            return $derPubKey;
        else
            return false;

    }

    /***
     * Check signature with public key R & S values of the signature and the message hash.
     *
     * @param $pubKey
     * @param $R
     * @param $S
     * @param $hash
     * @return bool
     */
    public function checkSignaturePoints($pubKey, $R, $S, $hash)
    {
        $G = $this->G;

        $pubKeyPts = $this->getPubKeyPointsWithDerPubKey($pubKey);

        // S^-1* hash * G + S^-1 * R * Qa

        // S^-1* hash
        $exp1 =  gmp_strval(
                            gmp_mul(
                                    gmp_invert(
                                               gmp_init($S, 16),
                                               $this->n
                                    ),
                                    gmp_init($hash, 16)
                            ),
                            16
                 );

        // S^-1* hash * G
        $exp1Pt = $this->mulPoint($exp1, $G);


        // S^-1 * R
        $exp2 =  gmp_strval(
                            gmp_mul(
                                    gmp_invert(
                                               gmp_init($S, 16),
                                                $this->n
                                    ),
                                    gmp_init($R, 16)
                            ),
                            16
                 );
        // S^-1 * R * Qa

        $pubKeyPts['x'] = gmp_init($pubKeyPts['x'], 16);
        $pubKeyPts['y'] = gmp_init($pubKeyPts['y'], 16);

        $exp2Pt = $this->mulPoint($exp2,$pubKeyPts);

        $resultingPt = $this->addPoints($exp1Pt, $exp2Pt);

        $xRes = gmp_strval($resultingPt['x'], 16);

        while(strlen($xRes) < 64)
            $xRes = '0' . $xRes;

        if(strtoupper($xRes) == strtoupper($R))
            return true;
        else
            return false;
    }

    /***
     * checkSignaturePoints wrapper for DER signatures
     *
     * @param $pubKey
     * @param $signature
     * @param $hash
     * @return bool
     */
    public function checkDerSignature($pubKey, $signature, $hash)
    {
        $signature = hex2bin($signature);
        if('30' != bin2hex(substr($signature, 0, 1)))
            return false;

        $RLength = hexdec(bin2hex(substr($signature, 3, 1)));
        $R = bin2hex(substr($signature, 4, $RLength));

        $SLength = hexdec(bin2hex(substr($signature, $RLength + 5, 1)));
        $S = bin2hex(substr($signature, $RLength + 6, $SLength));

        //echo "\n\nsignature:\n";
        //print_r(bin2hex($signature));

        //echo "\n\nR:\n";
        //print_r($R);
        //echo "\n\nS:\n";
        //print_r($S);

        return $this->checkSignaturePoints($pubKey, $R, $S, $hash);
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $rawMessage
     * @return bool
     */
    public function checkSignatureForRawMessage($rawMessage)
    {
        //recover message.
        preg_match_all("#-----BEGIN BITCOIN SIGNED MESSAGE-----\n(.{0,})\n-----BEGIN SIGNATURE-----\n#USi", $rawMessage, $out);
        $message = $out[1][0];

        preg_match_all("#\n-----BEGIN SIGNATURE-----\n(.{0,})\n(.{0,})\n-----END BITCOIN SIGNED MESSAGE-----#USi", $rawMessage, $out);
        $address = $out[1][0];
        $signature = $out[2][0];

        return $this->checkSignatureForMessage($address, $signature, $message);
    }

    /***
     * checks the signature of a bitcoin signed message.
     *
     * @param $address
     * @param $encodedSignature
     * @param $message
     * @return bool
     */
    public function checkSignatureForMessage($address, $encodedSignature, $message)
    {
        $hash = $this->hash256("\x18Bitcoin Signed Message:\n" . $this->numToVarIntString(strlen($message)) . $message);

        //recover flag
        $signature = base64_decode($encodedSignature);

        $flag = hexdec(bin2hex(substr($signature, 0, 1)));

        $R = bin2hex(substr($signature, 1, 32));
        $S = bin2hex(substr($signature, 33, 64));

        $derPubKey = $this->getPubKeyWithRS($flag, $R, $S, $hash);

        $recoveredAddress = $this->getAddress($derPubKey);

        if($address == $recoveredAddress)
            return true;
        else
            return false;
    }
}

?>
