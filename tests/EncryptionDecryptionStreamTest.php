<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;

use GuzzleHttp\Psr7\Stream;
use Orchestra\Testbench\TestCase;
use SmaatCoda\EncryptedFilesystem\Compression\Zlib\CompressionStream;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\DecryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\EncryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\EncryptionMethod;

class EncryptionDecryptionStreamTest extends TestCase
{
    protected $storagePath;
    protected $testFileName;
    protected $key;

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
        $encryptionMethod = new EncryptionMethod(openssl_random_pseudo_bytes(16));

        $inputFilePath = $this->storagePath . '/' . $this->testFileName;
        $outputFilePath = $this->storagePath . '/' . time() .'-encrypted-' . $this->testFileName;

        if ($this->compressionEnabled) {
            $inputOriginalStream = new CompressionStream(fopen($inputFilePath, 'rb'));
        } else {
            $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));
        }

        $inputEncryptedStream = new EncryptingStreamDecorator($inputOriginalStream, $encryptionMethod, $this->key);
        $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        $encryptedTextLength = 0;
        while (!$inputEncryptedStream->eof()) {
            $encryptedText = $inputEncryptedStream->read(EncryptingStreamDecorator::BLOCK_LENGTH);
            $outputStream->write($encryptedText);
            $encryptedTextLength += strlen($encryptedText);
        }

        $this->assertTrue($inputEncryptedStream->eof());

        return $outputFilePath;
    }

    /**
     * @covers DecryptingStreamDecorator::eof
     * @covers DecryptingStreamDecorator::read
     * @depends test_encryption_decorator
     */
    public function test_decryption_decorator($inputFilePath)
    {
        $controlFilePath = $this->storagePath . '/' . $this->testFileName;
        $outputFilePath = $this->storagePath . '/' . time() .'-decrypted-' . $this->testFileName;

        $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));

        $iv = $inputOriginalStream->read(DecryptingStreamDecorator::BLOCK_LENGTH);
        $encryptionMethod = new EncryptionMethod($iv);

        $inputDecryptedStream = new DecryptingStreamDecorator($inputOriginalStream, $encryptionMethod, $this->key);

        if ($this->compressionEnabled) {
            $outputStream = new CompressionStream(fopen($outputFilePath, 'wb'));
        } else {
            $outputStream = new Stream(fopen($outputFilePath, 'wb'));
        }

        while (!$inputDecryptedStream->eof()) {
            $plainText = $inputDecryptedStream->read(DecryptingStreamDecorator::BLOCK_LENGTH);

            $outputStream->write($plainText);
        }

        $this->assertTrue($inputDecryptedStream->eof());

        $controlContents = file_get_contents($controlFilePath);
        $outputContents = file_get_contents($outputFilePath);

        unlink($inputFilePath);
        unlink($outputFilePath);

        $this->assertEquals($controlContents, $outputContents);
    }
}
