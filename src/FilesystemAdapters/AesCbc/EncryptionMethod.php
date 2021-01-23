<?php

namespace SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc;

use LogicException;
use InvalidArgumentException;
use SmaatCoda\EncryptedFilesystem\Interfaces\EncryptionMethodInterface;

class EncryptionMethod implements EncryptionMethodInterface
{
    const ENCRYPTION_BLOCK_SIZE = 16;

    protected $currentIv;

    protected $iv;

    protected $keyLength;

    public function __construct($iv, $keyLength = 256)
    {
        $this->iv = $this->currentIv = $iv;
        $this->keyLength = $keyLength;
        if (strlen($iv) !== openssl_cipher_iv_length($this->getOpenSslMethod())) {
            throw new InvalidArgumentException('Invalid initialization vector');
        }
    }

    public function getOpenSslMethod()
    {
        return "aes-{$this->keyLength}-cbc";
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
        $this->currentIv = substr($cipherTextBlock, self::ENCRYPTION_BLOCK_SIZE * -1);
    }
}
