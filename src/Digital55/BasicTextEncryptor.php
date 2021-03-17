<?php

namespace Digital55;

class BasicTextEncryptor
{
    /**
     * @var string
     */
    private $password = "";

    /**
     * @var Cipher
     */
    private $encryptor;

    /**
     * BasicTextEncryptor constructor.
     * @param Cipher|null $cipher
     */
    public function __construct(Cipher $cipher = null)
    {
        if ($cipher) {
            $this->encryptor = $cipher;
        } else {
            $this->encryptor = new DESCipher();
        }
    }

    /**
     * @param string $password
     */
    public function setPassword(string $password)
    {
        $this->password = $password;
    }

    /**
     * @param string $message
     * @return string
     */
    public function encrypt(string $message): string
    {
        if ($message && $this->password) {
            $this->encryptor->setPassword($this->password);
            $cipherText = $this->encryptor->encrypt($message);
            return $this->base64Encode($cipherText);
        } else {
            return "";
        }
    }

    /**
     * @param string $message
     * @return string
     */
    public function decrypt(string $message): string
    {
        $decodedData = base64_decode($message);

        if ($decodedData && $this->password) {
            $this->encryptor->setPassword($this->password);
            $salt = substr($decodedData, 0, 8);
            $encrypted = substr($decodedData, 8);

            $this->encryptor->setSalt($salt);

            if ($encrypted) {
                return $this->encryptor->decrypt($encrypted);
            }
        }

        return "";
    }

    /**
     * @param $cipherText
     * @return string
     */
    private function base64Encode($cipherText): string
    {
        $salt = $this->encryptor->getSalt();
        $cipherText = $salt . $cipherText;
        return base64_encode($cipherText);
    }
}
