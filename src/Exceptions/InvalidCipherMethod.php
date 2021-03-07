<?php

namespace SmaatCoda\EncryptedFilesystem\Exceptions;

use Exception;
use Throwable;

class InvalidCipherMethod extends Exception
{
    public function __construct(string $cipherMethod)
    {
        $message = "\"$cipherMethod\" must implement SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface.";
        parent::__construct($message);
    }
}