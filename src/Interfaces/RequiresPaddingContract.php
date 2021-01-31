<?php


namespace SmaatCoda\EncryptedFilesystem\Interfaces;


interface RequiresPaddingContract
{
    public function getPaddingSize(int $filesize): int;
}