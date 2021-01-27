<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;

use GuzzleHttp\Psr7\Stream;
use Orchestra\Testbench\TestCase;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\DecryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\EncryptingStreamDecorator;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc\EncryptionMethod;

class CompressionTest extends TestCase
{
    protected $sourceFile;
    protected $compressedFile;
    protected $decompressedFile;

    public function setUp(): void
    {
        $this->sourceFile = 'https://scontent.fkiv5-1.fna.fbcdn.net/v/t1.0-9/19642617_877650985716445_4225178475141011156_n.jpg?_nc_cat=104&ccb=2&_nc_sid=09cbfe&_nc_ohc=v8eT9G4EqDsAX-74aL8&_nc_ht=scontent.fkiv5-1.fna&oh=5b28196cd60e359c5f196ce89075dc4d&oe=6038747E';
        $this->compressedFile = dirname(__DIR__) . '/storage/test-file-compressed.txt';
        $this->decompressedFile = dirname(__DIR__) . '/storage/test-file-decompressed.txt';
    }

    public function test_compression()
    {
        // Compressing
        $compressedString = '';
        $compressingStream = fopen($this->sourceFile, 'r');
        stream_filter_append($compressingStream, 'zlib.deflate', STREAM_FILTER_READ, ['level' => 9, 'window' => 15, 'memory' => 9]);

        while (!feof($compressingStream)) {
            $compressedString .= fread($compressingStream, 16);
        }

        $compressedOutput = fopen($this->compressedFile, 'wb');
        fwrite($compressedOutput, $compressedString);


        // Decompressing
        $decompressedString = '';
        $decompressedStream = fopen($this->compressedFile, 'r');
        stream_filter_append($decompressedStream, 'zlib.inflate', STREAM_FILTER_READ, ['level' => 9, 'window' => 15, 'memory' => 9]);

        while (!feof($decompressedStream)) {
            $decompressedString .= fread($decompressedStream, 16);
        }

        $testFileCompressed = fopen($this->decompressedFile, 'wb');
        fwrite($testFileCompressed, $decompressedString);

        dd(strlen(file_get_contents($this->sourceFile)), filesize($this->compressedFile), filesize($this->decompressedFile));
        $this->assertLessThan(filesize($this->compressedFile), filesize($this->decompressedFile));
    }
}
