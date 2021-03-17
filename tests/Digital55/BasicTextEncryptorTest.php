<?php
/*
 *     PBEWithMD5AndDES is a password-based encryption algorithm defined in PKCS #5 Specification.
 *     Copyright (C) 2021 Manuel Maldonado <manuel.maldonado@digital55.com>, Jose Antonio Arenal <joseantonio.arenal@digital55.com>
 *
 *     This program is free software: you can redistribute it and/or modify
 *     it under the terms of the GNU General Public License as published by
 *     the Free Software Foundation, either version 3 of the License, or
 *     (at your option) any later version.
 *
 *     This program is distributed in the hope that it will be useful,
 *     but WITHOUT ANY WARRANTY; without even the implied warranty of
 *     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *     GNU General Public License for more details.
 *
 *     You should have received a copy of the GNU General Public License
 *     along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

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