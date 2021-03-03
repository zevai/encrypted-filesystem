<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;


use Illuminate\Filesystem\Filesystem;

class EncryptedStorageTest extends TestCase
{
    /** @var Filesystem */
    protected $storage;

    public function setUp(): void
    {
        parent::setUp();
        $this->storage = $this->app['filesystem']->disk('encrypted-disk');
    }

    /**
     * @covers \SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter::get
     * @covers \SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter::put
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function test_storage()
    {
//        $contents = file_get_contents(dirname(__DIR__) . '/storage/CV.pdf');
//        $this->storage->put('CV-encrypted.pdf', $contents);

//        $contents2 = $this->storage->get('CV-encrypted.pdf');
//        file_put_contents(dirname(__DIR__) . '/storage/CV-decrypted.pdf', $contents2);
    }

}
