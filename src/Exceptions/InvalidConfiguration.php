<?php

namespace SmaatCoda\EncryptedFilesystem\Exceptions;

use Exception;
use Throwable;

class InvalidConfiguration extends Exception
{
    public function __construct(string $key)
    {
        $message = "Please make sure your configuration contains a valid \"$key\" entry.";
        parent::__construct($message);
    }
}