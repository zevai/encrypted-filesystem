<?php

namespace SmaatCoda\EncryptedFilesystem\Tests;

use GuzzleHttp\Psr7\Stream;
use Orchestra\Testbench\TestCase;
use SmaatCoda\EncryptedFilesystem\Compression\Zlib\CompressionStream;
use SmaatCoda\EncryptedFilesystem\Compression\Zlib\DecompressedStream;

class CompressionTest extends TestCase
{
    protected $sourceFile;
    protected $compressedFile;
    protected $decompressedFile;

    public function setUp(): void
    {
        $this->sourceFile = dirname(__DIR__) . '/storage/test-file.txt';
        $this->compressedFile = dirname(__DIR__) . '/storage/test-file-compressed.txt';
        $this->decompressedFile = dirname(__DIR__) . '/storage/test-file-decompressed.txt';
    }

    /**
     * @covers CompressionStream::read
     * @covers DecompressedStream::read
     */
    public function test_compression()
    {
        // Compressing
        $compressingStream = new CompressionStream(fopen($this->sourceFile, 'rw'));
        $compressedOutput = new Stream(fopen($this->compressedFile, 'wb'));

        while (!$compressingStream->eof()) {
            $compressedOutput->write($compressingStream->read(16));
        }

        // Decompressing
        $decompressedStream = new DecompressedStream(fopen($this->compressedFile, 'r'));
        $decompressedOutput = new Stream(fopen($this->decompressedFile, 'wb'));

        while (!$decompressedStream->eof()) {
            $decompressedOutput->write($decompressedStream->read(16));
        }

        $this->assertLessThan(filesize($this->decompressedFile), filesize($this->compressedFile));

        unlink($this->compressedFile);
        unlink($this->decompressedFile);
    }
}
