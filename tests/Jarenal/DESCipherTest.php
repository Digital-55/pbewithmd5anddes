<?php


use Digital55\DESCipher;
use PHPUnit\Framework\TestCase;

final class DESCipherTest extends TestCase
{
    public function testGetSaltFromHexCorrectLength()
    {
        $password = "12345678";
        $saltHEX = "91DEA881F089AFB2";
        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltHEX);
        $salt = $encryptor->getSalt();
        $expected = pack("H*", $saltHEX);
        $this->assertEquals($expected, $salt);
        $total_bytes = strlen($salt);
        $this->assertEquals(8, $total_bytes);
    }

    public function testGetSaltFromHexWrongLength()
    {
        $password = "12345678";
        $saltHEX = "91DEA881F089AFB2DE";
        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltHEX);
        $salt = $encryptor->getSalt();
        $expected = "";
        $this->assertEquals($expected, $salt);
        $total_bytes = strlen($salt);
        $this->assertEquals(0, $total_bytes);
    }

    public function testGetRandomSaltReturnsCorrectLength()
    {
        $password = "12345678";
        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->init();
        $salt = $encryptor->getSalt();
        $total_bytes = strlen($salt);
        $this->assertEquals(8, $total_bytes);
    }

    public function testGetSaltFromStringCorrectLength()
    {
        $password = "12345678";
        $saltString = "abcdefgh";
        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltString);
        $salt = $encryptor->getSalt();
        $expected = $saltString;
        $this->assertEquals($expected, $salt);
        $total_bytes = strlen($salt);
        $this->assertEquals(8, $total_bytes);
    }

    public function testGetSaltFromStringWrongLength()
    {
        $password = "12345678";
        $saltString = "abcdefgh1234";
        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltString);
        $salt = $encryptor->getSalt();
        $expected = "";
        $this->assertEquals($expected, $salt);
        $total_bytes = strlen($salt);
        $this->assertEquals(0, $total_bytes);
    }


    public function testGetKey()
    {
        $password = "12345678";
        $saltHEX = "91DEA881F089AFB2";

        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltHEX);
        $encryptor->init();

        $key = $encryptor->getKey();
        $expected = pack("H*", "601BB1AFF28D8B2A");
        $this->assertEquals($expected, $key);
        $total_bytes = strlen($key);
        $this->assertEquals(8, $total_bytes);
    }

    public function testGetIv()
    {
        $password = "12345678";
        $saltHEX = "91DEA881F089AFB2";

        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltHEX);
        $encryptor->init();

        $iv = $encryptor->getIV();
        $expected = pack("H*", "0C0CEA00A8B7BE89");
        $this->assertEquals($expected, $iv);
        $total_bytes = strlen($iv);
        $this->assertEquals(8, $total_bytes);
    }

    public function testEncrypt()
    {
        $password = "12345678";
        $saltHEX = "91DEA881F089AFB2";

        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltHEX);
        $expected = pack("H*", "75B614432E72D65188FF4ACF4F27ADFF");
        $encrypted = $encryptor->encrypt("Hola Mundo!");
        $this->assertEquals($expected, $encrypted);
    }

    public function testDecrypt()
    {
        $password = "12345678";
        $saltHEX = "91DEA881F089AFB2";

        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encryptor->setSalt($saltHEX);
        $encrypted = pack("H*", "75B614432E72D65188FF4ACF4F27ADFF");
        $decrypted = $encryptor->decrypt($encrypted);
        $this->assertEquals("Hola Mundo!", $decrypted);
    }

    public function testEncryptAndDecryptUsingRandomSalt()
    {
        $password = "12345678";
        $message = "Hola Mundo!";

        $encryptor = new DESCipher();
        $encryptor->setPassword($password);
        $encrypted = $encryptor->encrypt($message);
        $salt1 = $encryptor->getSalt();

        $encryptor2 = new DESCipher();
        $encryptor2->setPassword($password);
        $encryptor2->setSalt($salt1);
        $decrypted = $encryptor2->decrypt($encrypted);

        $expected = $message;
        $this->assertEquals($expected, $decrypted);
    }
}