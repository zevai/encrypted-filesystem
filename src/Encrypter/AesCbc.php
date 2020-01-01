<?php


namespace SmaatCoda\EncryptedFilesystem\Encrypter;

use LogicException;
use InvalidArgumentException;

class AesCbc implements CipherInterface
{
    const ENCRYPTION_BLOCK_SIZE = 16;

    protected $currentIv;

    protected $iv;

    protected $keySize;

    public function __construct($iv, $keySize = 256)
    {
        $this->iv = $this->currentIv = $iv;
        $this->keySize = $keySize;
        if (strlen($iv) !== openssl_cipher_iv_length($this->getOpenSslMethod())) {
            throw new InvalidArgumentException('Invalid initialization vector');
        }
    }


    public function getOpenSslMethod()
    {
        return "aes-{$this->keySize}-cbc";
    }

    public function requiresPadding()
    {
        return true;
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($offset === 0 && $whence === SEEK_SET) {
            $this->currentIv = $this->iv;
        } else {
            throw new LogicException('Only rewinding is supported');
        }
    }

    public function getCurrentIv()
    {
        return $this->currentIv;
    }

    public function update($cipherTextBlock)
    {
        $this->currentIv = substr($cipherTextBlock, self::BLOCK_SIZE * -1);
    }

}