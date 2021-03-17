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

namespace Digital55;

use Exception;
use Normalizer;

final class DESCipher implements Cipher
{
    private const CIPHER_ALGO = "des-cbc";

    /**
     * @var string
     */
    private $password = "";

    /**
     * @var string
     */
    private $salt = "";

    /**
     * @var string
     */
    private $key = "";

    /**
     * @var string
     */
    private $iv = "";

    /**
     * @var string
     */
    private $derivedKey = "";

    /**
     * @var int
     */
    private $iterations = 1000;

    /**
     * @var int
     */
    private $blockSize = 8;

    /**
     * Initialize Salt, derivedKey, Key and IV
     */
    public function init(): void
    {
        if (!$this->salt) {
            $this->salt = $this->generateSalt();
        }

        $this->derivedKey = $this->generateDerivedKey();
    }

    /**
     * @param string $message
     * @return false|string
     */
    public function encrypt(string $message): string
    {
        if (!$this->getSalt() || !$this->getKey() || !$this->getIV()) {
            $this->init();
        }

        $message = $this->addPadding($message);
        $messageLen = strlen($message);
        $ciphertext = openssl_encrypt(
            $message,
            self::CIPHER_ALGO,
            $this->getKey(),
            OPENSSL_RAW_DATA,
            $this->getIV()
        );

        if ($ciphertext === false) {
            return false;
        }

        $ciphertext = substr($ciphertext, 0, $messageLen);
        return $ciphertext;
    }

    /**
     * @param string $message
     * @return false|string
     */
    public function decrypt(string $message): string
    {
        if (!$this->getSalt() || !$this->getKey() || !$this->getIV()) {
            $this->init();
        }

        return openssl_decrypt(
            $message,
            self::CIPHER_ALGO,
            $this->getKey(),
            OPENSSL_RAW_DATA,
            $this->getIV()
        );
    }

    /**
     * A salt in HEX or RAW format
     *
     * @param string $salt
     */
    public function setSalt(string $salt)
    {
        if ($salt) {
            if (ctype_xdigit($salt)) {
                $salt = pack("H*", $salt);
            }

            $totalBytes = strlen($salt);

            if ($totalBytes === 8) {
                $this->salt = $salt;
            }
        }
    }

    /**
     * @return string
     */
    public function getSalt(): string
    {
        return $this->salt;
    }

    /**
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * @return string
     */
    public function getIV(): string
    {
        return $this->iv;
    }

    /**
     * @param string $password
     */
    public function setPassword(string $password)
    {
        // Normalize password to NFC form
        $this->password = Normalizer::normalize($password, Normalizer::FORM_C);
    }

    /**
     * @return string
     */
    private function generateDerivedKey(): string
    {
        $toBeHashed = md5($this->password . $this->getSalt(), true);

        for ($i = 1; $i < $this->iterations; $i++) {
            $toBeHashed = md5($toBeHashed, true);
        }

        $this->key = substr($toBeHashed, 0, 8);
        $this->iv = substr($toBeHashed, 8, 8);
        return $toBeHashed;
    }

    /**
     * @return false|string
     */
    private function generateSalt()
    {
        try {
            return random_bytes(8);
        } catch (Exception $e) {
            return false;
        }
    }

    /**
     * @param string $message
     * @return string
     */
    private function addPadding(string $message): string
    {
        $padding = $this->blockSize - strlen($message) % $this->blockSize;
        $message .= str_repeat(pack('C', $padding), $padding);
        return $message;
    }
}
