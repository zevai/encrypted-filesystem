<?php

namespace SmaatCoda\EncryptedFilesystem;

use Illuminate\Filesystem\FilesystemAdapter;
use Illuminate\Support\Facades\Storage;
use League\Flysystem\Adapter\Local;
use League\Flysystem\FileNotFoundException;
use League\Flysystem\FilesystemInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface;

class EncryptedFilesystemAdapter extends Local
{
    /**
     * This extension is appended to encrypted files and will be checked for before decryption
     */
    const FILENAME_POSTFIX = '.enc';

    /**
     * @var CipherMethodInterface
     */
    protected $cipherMethod;

    /**
     * EncryptedFilesystemAdapter constructor.
     * @param CipherMethodInterface $cipherMethod
     * @param $root
     * @param int $writeFlags
     * @param int $linkHandling
     * @param array $permissions
     */
    public function __construct(CipherMethodInterface $cipherMethod, $root, $writeFlags = LOCK_EX, $linkHandling = self::DISALLOW_LINKS, array $permissions = [])
    {
        $this->cipherMethod = $cipherMethod;

        parent::__construct($root, $writeFlags, $linkHandling, $permissions);
    }

    /**
     * @param $destPath
     * @return string
     */
    protected function attachEncryptionMarkers($destPath)
    {
        return $destPath . self::FILENAME_POSTFIX;
    }

    /**
     * @param $sourceRealPath
     * @return string|string[]|null
     */
    protected function detachEncryptionMarkers($sourceRealPath)
    {
        return preg_replace('/(' . self::FILENAME_POSTFIX . ')$/', '', $sourceRealPath);
    }
}