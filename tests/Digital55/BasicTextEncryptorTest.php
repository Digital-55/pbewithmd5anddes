<?php


use Digital55\BasicTextEncryptor;
use Digital55\DESCipher;
use PHPUnit\Framework\TestCase;

final class BasicTextEncryptorTest extends TestCase
{
    public function testEncryptAndDecrypt()
    {
        $password = "12345678";
        $saltHEX = "91DEA881F089AFB2";
        $message = "Hola Mundo!";

        $encryptor = new DESCipher();
        $encryptor->setSalt($saltHEX);
        $basicEncryptor = new BasicTextEncryptor($encryptor);
        $basicEncryptor->setPassword($password);
        $encrypted = $basicEncryptor->encrypt($message);
        $expected = "kd6ogfCJr7J1thRDLnLWUYj/Ss9PJ63/";
        $this->assertEquals($expected, $encrypted);
    }

    public function testDecrypt()
    {
        $password = "12345678";
        $encrypted = "p0AAoDZ422PrQLfe8dL2XqOHW/ZFW6FU";

        $encryptor = new DESCipher();
        $basicEncryptor = new BasicTextEncryptor($encryptor);
        $basicEncryptor->setPassword($password);
        $message = $basicEncryptor->decrypt($encrypted);
        $expected = "Hola Mundo!";
        $this->assertEquals($expected, $message);
    }
}