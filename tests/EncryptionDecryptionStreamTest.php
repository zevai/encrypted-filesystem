<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;

use GuzzleHttp\Psr7\Stream;
use Orchestra\Testbench\TestCase;
use SmaatCoda\EncryptedFilesystem\Compression\Zlib\CompressionStream;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\DecryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\EncryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\OpenSslCipherMethod;

class EncryptionDecryptionStreamTest extends TestCase
{
    protected $storagePath;
    protected $testFileName;
    protected $encryptionKey;

    protected $compressionEnabled = true;

    public function setUp(): void
    {
        $this->encryptionKey = 'io0GXLA0l3AmuZUPnEqB';
        $this->storagePath = dirname(__DIR__) . '/storage';
        $this->testFileName = 'test-file.txt';
    }

    /**
     * @covers EncryptingStreamDecorator::eof
     * @covers EncryptingStreamDecorator::read
     * @return string
     */
    public function test_encryption_decorator()
    {
        $encryptionMethod = new OpenSslCipherMethod($this->encryptionKey);

        $inputFilePath = $this->storagePath . '/' . $this->testFileName;
        $outputFilePath = $this->storagePath . '/' . time() . '-encrypted-' . $this->testFileName;

        if ($this->compressionEnabled) {
            $inputOriginalStream = new CompressionStream(fopen($inputFilePath, 'rb'));
        } else {
            $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));
        }

        $inputEncryptedStream = new EncryptingStreamDecorator($inputOriginalStream, $encryptionMethod);
        $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        while (!$inputEncryptedStream->eof()) {
            $outputStream->write($inputEncryptedStream->read(7));
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

        $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));

        $encryptionMethod = new OpenSslCipherMethod($this->encryptionKey);

        $inputDecryptedStream = new DecryptingStreamDecorator($inputOriginalStream, $encryptionMethod);

        if ($this->compressionEnabled) {
            $outputStream = new CompressionStream(fopen($outputFilePath, 'wb'));
        } else {
            $outputStream = new Stream(fopen($outputFilePath, 'wb'));
        }

        while (!$inputDecryptedStream->eof()) {
            $outputStream->write($inputDecryptedStream->read(4));
        }

        $this->assertTrue($inputDecryptedStream->eof());

        $controlContents = file_get_contents($controlFilePath);
        $outputContents = file_get_contents($outputFilePath);

        unlink($inputFilePath);
        unlink($outputFilePath);

        $this->assertEquals($controlContents, $outputContents);
    }
}
