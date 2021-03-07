<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;


use GuzzleHttp\Psr7\Stream;
use Illuminate\Filesystem\Filesystem;
use SmaatCoda\EncryptedFilesystem\CipherMethods\OpenSslCipherMethod;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\DecryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\EncryptingStreamDecorator;

class EncryptedStorageTest extends TestCase
{
    /** @var Filesystem */
    protected $storage;

    /** @var string */
    protected $testFileName;

    /** @var string */
    protected $storagePath;

    /** @var string */
    protected $encryptionKey;

    public function setUp(): void
    {
        parent::setUp();
        $this->storage = $this->app['filesystem']->disk('encrypted-disk');
        $this->testFileName = 'CV.pdf';
        $this->storagePath = dirname(__DIR__) . '/storage';
        $this->encryptionKey = config('filesystems.disks.encrypted-disk.key');
    }

    /**
     * @covers EncryptingStreamDecorator::eof
     * @covers EncryptingStreamDecorator::read
     * @return string
     */
    public function test_encryption_decorator()
    {
        $inputFilePath = $this->storagePath . '/' . $this->testFileName;
        $outputFilePath = $this->storagePath . '/' . time() . '-encrypted-' . $this->testFileName;

        // This driver works exclusively with streams, so transform the contents into a stream
        $stream = fopen('php://memory','r+');
        fwrite($stream, file_get_contents($inputFilePath));
        rewind($stream);

        $cipherMethod = new OpenSslCipherMethod($this->encryptionKey);
        $inputOriginalStream = new Stream($stream);
        $inputEncryptedStream = new EncryptingStreamDecorator($inputOriginalStream, $cipherMethod);
        $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        while (!$inputEncryptedStream->eof()) {
            $outputStream->write($inputEncryptedStream->read($cipherMethod->getBlockSize()));
        }

        $this->assertTrue($inputEncryptedStream->eof());

        return $outputFilePath;
    }

    /**
     * @covers  DecryptingStreamDecorator::eof
     * @covers  DecryptingStreamDecorator::read
     * @depends test_encryption_decorator
     */
    public function test_decryption_decorator($inputFilePath)
    {
        $controlFilePath = $this->storagePath . '/' . $this->testFileName;
        $outputFilePath = $this->storagePath . '/' . time() . '-decrypted-' . $this->testFileName;

        $cipherMethod = new OpenSslCipherMethod($this->encryptionKey);
        $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));
        $inputDecryptedStream = new DecryptingStreamDecorator($inputOriginalStream, $cipherMethod);
        $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        while (!$inputDecryptedStream->eof()) {
            $outputStream->write($inputDecryptedStream->read($cipherMethod->getBlockSize()));
        }

        $this->assertTrue($inputDecryptedStream->eof());

        $controlContents = file_get_contents($controlFilePath);
        $outputContents = file_get_contents($outputFilePath);

        unlink($inputFilePath);
        unlink($outputFilePath);

        $this->assertEquals($controlContents, $outputContents);
    }

    /**
     * @covers \SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter::put
     * @covers \SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter::move
     * @covers \SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter::copy
     * @covers \SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter::exists
     * @covers \SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter::delete
     * @throws \Illuminate\Contracts\Filesystem\FileNotFoundException
     */
    public function test_storage()
    {
        $encryptedPath = time() . "-encrypted-{$this->testFileName}";
        $movedPath = time() . "-encrypted-moved-{$this->testFileName}";
        $copiedPath = time() . "-encrypted-copied-{$this->testFileName}";

        $originalContents = file_get_contents(dirname(__DIR__) . "/storage/{$this->testFileName}");

        $this->storage->put($encryptedPath, $originalContents);
        $this->assertTrue($this->storage->exists($encryptedPath), 'encryption failed');
        $this->storage->move($encryptedPath, $movedPath);
        $this->assertTrue($this->storage->exists($movedPath), 'moving failed');
        $this->storage->copy($movedPath, $copiedPath);
        $this->assertTrue($this->storage->exists($copiedPath), 'copying failed');

        $resultContents = $this->storage->get($copiedPath);

        $this->assertEquals($originalContents, $resultContents);

        $this->storage->delete([$copiedPath, $movedPath]);
        $this->assertFalse($this->storage->exists($movedPath), 'delete failed');
        $this->assertFalse($this->storage->exists($copiedPath), 'delete failed');

    }

}
