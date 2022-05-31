<?php

use Mdanter\Ecc\Crypto\Key\PrivateKey;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Serializer\Signature\DerSignatureSerializer;
use HonPhpsm\ecc\RtEccFactory;
use HonPhpsm\sm\RtSm2;

require '../vendor/autoload.php';

$data = '{"request":{"body":{"TEST":"中文","TEST2":"!@#$%^&*()","TEST3":12345,"TEST4":[{"arrItem1":"qaz","arrItem2":123,"arrItem3":true,"arrItem4":"中文"}],"buscod":"N02030"},"head":{"funcode":"DCLISMOD","userid":"N003261207"}},"signature":{"sigdat":"__signature_sigdat__"}}';
// $key = 'NBtl7WnuUtA2v5FaebEkU0/Jj1IodLGT6lQqwkzmd2E=';
$key = 'D5F2AFA24E6BA9071B54A8C9AD735F9A1DE9C4657FA386C09B592694BC118B38';
// $key = 'a7763cd4fe7db2a2146fc09bf2d5e5a30e10c51b7e4bed00b3a26ec79ba78ff3';
// $key = bin2hex(base64_decode($key)); //转为16进制
$sm2 = new RtSm2('base64');
// $userid = 'N003261207' . "0000000000000000";
$userid = "12345678123456789";
$userid = substr($userid, 0, 16);

$sign = $sm2->doSign($data, $key, $userid);
var_dump($sign);
var_dump('-------------------------');
$sign = base64_decode($sign);
$a = \FG\ASN1\ASNObject::fromBinary($sign)->getChildren();

$aa = formatHex($a[0]->getContent());
$bb = formatHex($a[1]->getContent());
$sign = $aa . $bb;
$sign = base64_encode(hex2bin($sign));
var_dump($sign);


$signHex = bin2hex(base64_decode($sign));
var_dump($signHex);
$r = substr($signHex, 0, 64);
$s = substr($signHex, 64, 64);
var_dump($r, $s);
$r = gmp_init($r, 16);
$s = gmp_init($s, 16);
/*$r = gmp_init('90416529259334433398865842692135340273188180784859666141339740103133164395295', 10);
$s = gmp_init('51927610271972364114244381230895889971736075490328811928131691394657016568041', 10);*/
$signature = new Signature($r, $s);
$serializer = new DerSignatureSerializer();
$serializedSig = $serializer->serialize($signature);

$sign = base64_encode($serializedSig);
var_dump($sign);
$adapter = RtEccFactory::getAdapter();
$generator = RtEccFactory::getSmCurves()->generatorSm2();
$secret = gmp_init($key, 16);
$key = new PrivateKey($adapter, $generator, $secret);
$pubkey = $key->getPublicKey()->getPoint();
$x = $pubkey->getX();
$y = $pubkey->getY();
var_dump('------------------');
var_dump($x);
var_dump($y);

$pub = gmp_strval($x, 16);
var_dump($pub);
$pub .= gmp_strval($y, 16);
var_dump($pub);
$pub = strtolower('E90F9F92DB2763D3853FE2E9491E5475BC5FE731C214ED0F98E2A514D4F10C81A5F23B0F6DB07FF444F6DCD57E69C4B3E05124CC3EF8B16DA288D54744B88A1E');
$b = $sm2->verifySign($data, $sign, $pub, $userid);
var_dump($b);


function formatHex($dec)
{

    $hex = gmp_strval(gmp_init($dec, 10), 16);
    $len = strlen($hex);
    if ($len == 64) {
        return $hex;
    }
    if ($len < 64) {
        $hex = str_pad($hex, 64, "0", STR_PAD_LEFT);
    } else {
        $hex = substr($hex, $len - 64, 64);
    }

    return $hex;
}
