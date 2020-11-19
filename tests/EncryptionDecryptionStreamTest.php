<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Stream;
use Orchestra\Testbench\TestCase;
use SmaatCoda\EncryptedFilesystem\Encrypter\EncryptionMethods\AesCbc;
use SmaatCoda\EncryptedFilesystem\Encrypter\StreamDecryptionDecorator;
use SmaatCoda\EncryptedFilesystem\Encrypter\StreamEncryptionDecorator;

class EncryptionDecryptionStreamTest extends TestCase
{
    protected $storagePath;
    protected $testFileName;
    protected $key;

    public function setUp()
    {
        $this->encryptionKey = 'io0GXLA0l3AmuZUPnEqB';
        $this->storagePath = dirname(__DIR__) . '/storage';
        $this->testFileName = 'test-file.txt';
    }

    public static function tearDownAfterClass()
    {

    }

    public function test_encryption_decorator()
    {
        $encryptionMethod = new AesCbc(openssl_random_pseudo_bytes(16));

        $inputFilePath = $this->storagePath . '/' . $this->testFileName;
        $outputFilePath = $this->storagePath . '/' . time() .'-encrypted-' . $this->testFileName;

        $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));

        $inputEncryptedStream = new StreamEncryptionDecorator($inputOriginalStream, $encryptionMethod, $this->key);
        $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        $encryptedTextLength = 0;
        $declaredLength = $inputEncryptedStream->getSize();
        while (!$inputEncryptedStream->eof()) {
            $encryptedText = $inputEncryptedStream->read(StreamEncryptionDecorator::BLOCK_LENGTH);
            $outputStream->write($encryptedText);
            $encryptedTextLength += strlen($encryptedText);
        }

        print_r("\n result file length: $encryptedTextLength; declared length: $declaredLength");

        $this->assertTrue($inputEncryptedStream->eof());

        return $outputFilePath;
    }

    /**
     * @depends test_encryption_decorator
     */
    public function test_decryption_decorator($inputFilePath)
    {

        $controlFilePath = $this->storagePath . '/' . $this->testFileName;
        $outputFilePath = $this->storagePath . '/' . time() .'-decrypted-' . $this->testFileName;

        $inputOriginalStream = new Stream(fopen($inputFilePath, 'rb'));
        $iv = $inputOriginalStream->read(StreamDecryptionDecorator::BLOCK_LENGTH);
        $encryptionMethod = new AesCbc($iv);

        $inputDecryptedStream = new StreamDecryptionDecorator($inputOriginalStream, $encryptionMethod, $this->key);
        $outputStream = new Stream(fopen($outputFilePath, 'wb'));

        while (!$inputDecryptedStream->eof()) {
            $encryptedText = $inputDecryptedStream->read(StreamDecryptionDecorator::BLOCK_LENGTH);

            $outputStream->write($encryptedText);
        }

        $this->assertTrue($inputDecryptedStream->eof());

        $controlContents = file_get_contents($controlFilePath);
        $outputContents = file_get_contents($outputFilePath);

        $controlContentsLength = filesize($controlFilePath);
        $outputContentsLength = filesize($outputFilePath);

        unlink($inputFilePath);
        unlink($outputFilePath);

//        print_r("\n files are identical: " . ($controlContents == $outputContents ? 'true' : 'false') . "; control length: $controlContentsLength; result length: $outputContentsLength");

        $this->assertEquals($controlContents, $outputContents);
    }
}
