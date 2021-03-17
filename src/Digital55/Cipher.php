<?php


namespace Digital55;

interface Cipher
{
    /**
     * @param string $message
     * @return false|string
     */
    public function encrypt(string $message): string;

    /**
     * @param string $message
     * @return string
     */
    public function decrypt(string $message): string;

    /**
     * @param string $password
     */
    public function setPassword(string $password);

    /**
     * @param string $salt
     */
    public function setSalt(string $salt);

    /**
     * @return string
     */
    public function getSalt(): string;
}
