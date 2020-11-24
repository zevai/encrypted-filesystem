<?php

namespace SmaatCoda\EncryptedFilesystem\Interfaces\EncryptionMethods;

interface EncryptionMethodInterface
{
    public function getOpenSslMethod();

    public function getCurrentIv();

    public function requiresPadding();

    public function seek($offset, $whence = SEEK_SET);

    public function update($cipherTextBlock);
}