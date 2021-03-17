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
