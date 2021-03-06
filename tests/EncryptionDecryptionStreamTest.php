<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;

use GuzzleHttp\Psr7\Stream;
use Illuminate\Support\Facades\Storage;
use Orchestra\Testbench\TestCase;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\DecryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\EncryptionStreams\EncryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\CipherMethods\OpenSslCipherMethod;

class EncryptionDecryptionStreamTest extends TestCase
{
    protected $storagePath;
    protected $testFileName;
    protected $encryptionKey;

    public function setUp(): void
    {
        $this->encryptionKey = 'io0GXLA0l3AmuZUPnEqB';
        $this->storagePath = dirname(__DIR__) . '/storage';
        $this->testFileName = 'CV.pdf';
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

        $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));

        $inputEncryptedStream = new EncryptingStreamDecorator($inputOriginalStream, $encryptionMethod);
        $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        while (!$inputEncryptedStream->eof()) {
            $outputStream->write($inputEncryptedStream->read(30));
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

            $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        while (!$inputDecryptedStream->eof()) {
            $outputStream->write($inputDecryptedStream->read(100));
        }

        $this->assertTrue($inputDecryptedStream->eof());

        $controlContents = file_get_contents($controlFilePath);
        $outputContents = file_get_contents($outputFilePath);

        unlink($inputFilePath);
        unlink($outputFilePath);

        $this->assertEquals($controlContents, $outputContents);
    }
}
