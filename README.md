# PBEWithMD5AndDES algorithm in PHP

PBEWithMD5AndDES is a password-based encryption algorithm defined in [PKCS #5 Specification](https://tools.ietf.org/html/rfc2898).

## How it works

This algorithm uses a password, and an 8 bytes random SALT (**S**) for to generate a 16 bytes Derived KEY (**DK**).

From the first 8 bytes of the DK we get a KEY (**K**) and from the next 8 bytes we get an initialization vector (**IV**).

The next step is padding the message (**M**) for to obtain a string that is a multiple of 8 bytes.

Next step is to encrypt **M** using **DES-CBD** algorithm using **K** and **IV** for to get a CIPHERTEXT (**C**).

We need to calculate the length from M (**ML**).

Now we have to extract from C only the first **ML** bytes for to obtain the FINAL CIPHERTEXT (**FC**). 

Finally, we will encode **S + FC** using a **BASE64** function.

## Tests

For to run PHPUnit Test Suite execute the next command from the root of the project.

```bash
$ ./vendor/bin/phpunit --bootstrap vendor/autoload.php tests
```

## Examples

Encrypt a string

```injectablephp
$password = "12345678";
$message = "En un lugar de la Mancha, de cuyo nombre no quiero acordarme...";
$textEncryptor = new BasicTextEncryptor();
$textEncryptor->setPassword($password);
$encrypted = $textEncryptor->encrypt($message);
echo "Encrypted message: " . $encrypted . PHP_EOL;
```

Decrypt a string

```injectablephp
$password = "12345678";
$encrypted = "pDvCZD6QmJpnv5Nu829EZM8OPBgIsz80gefgYXG4ZbMSJfewBkYzMLR1h2+GzeB652Ka/WLEvd841y1m3zWVWLlD5JiNwwHC";
$textEncryptor = new BasicTextEncryptor();
$textEncryptor->setPassword($password);
$decrypted = $textEncryptor->decrypt($encrypted);
echo "Decrypted message: " . $decrypted . PHP_EOL;
```

## Authors

* **Manuel Maldonado** - [manuel.maldonado@digital55.com](manuel.maldonado@digital55.com)
* **Jose Antonio Arenal** - [joseantonio.arenal@digital55.com](joseantonio.arenal@digital55.com)

## References

* [PKCS #5: Password-Based Cryptography Specification Version 2.0](https://tools.ietf.org/html/rfc2898)
* [Brief description at Java Security Standard Algorithm Names](https://docs.oracle.com/javase/9/docs/specs/security/standard-names.html#cipher-algorithm-names)
* [What Is PKCS5Padding?](http://www.herongyang.com/Cryptography/DES-JDK-What-Is-PKCS5Padding.html)
* [Inspired on JASYPT BasicTextEncryptor implementation](http://www.jasypt.org/api/jasypt/1.8/org/jasypt/util/text/BasicTextEncryptor.html)
* [Inspired on KevinBusse/PBEWithMD5AndDES implementation](https://github.com/KevinBusse/PBEWithMD5AndDES)

## License

This library is licensed under the GNU GPLv3 - see the [LICENSE](LICENSE) file for details.