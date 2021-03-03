<?php

namespace SmaatCoda\EncryptedFilesystem\Exceptions;

use Exception;
use Throwable;

class UnregisteredCipherMethod extends Exception
{
    public function __construct(string $cipherMethod)
    {
        $message = "No cipher method was registered under the $cipherMethod alias.";
        parent::__construct($message);
    }
}