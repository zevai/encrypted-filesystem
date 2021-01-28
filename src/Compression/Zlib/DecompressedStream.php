<?php


namespace SmaatCoda\EncryptedFilesystem\Compression\Zlib;


use GuzzleHttp\Psr7\Stream;

class DecompressedStream extends Stream
{
    public function __construct($stream, $options = [])
    {
        stream_filter_append($stream, 'zlib.inflate', STREAM_FILTER_READ, ['level' => 9, 'window' => 15, 'memory' => 9]);

        parent::__construct($stream, $options);
    }

    public function isWritable()
    {
        return false;
    }
}