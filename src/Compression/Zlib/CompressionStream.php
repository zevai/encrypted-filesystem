<?php


namespace SmaatCoda\EncryptedFilesystem\Compression\Zlib;


use GuzzleHttp\Psr7\Stream;

class CompressionStream extends Stream
{
    const DIRECTION_READ = 0;
    const DIRECTION_WRITE = 1;

    /**
     * CompressionStream constructor.
     * @param Stream|resource $stream
     * @param array $options
     */
    public function __construct($stream, $options = [])
    {
        if ($stream instanceof Stream) {
            $stream = $stream->detach();
        }

        if (isset($options['direction']) && $options['direction'] == self::DIRECTION_READ) {
            stream_filter_append($stream, 'zlib.deflate', STREAM_FILTER_READ, ['level' => 9, 'window' => 15, 'memory' => 9]);
            stream_filter_append($stream, 'zlib.inflate', STREAM_FILTER_WRITE, ['level' => 9, 'window' => 15, 'memory' => 9]);
        } else {
            stream_filter_append($stream, 'zlib.inflate', STREAM_FILTER_READ, ['level' => 9, 'window' => 15, 'memory' => 9]);
            stream_filter_append($stream, 'zlib.deflate', STREAM_FILTER_WRITE, ['level' => 9, 'window' => 15, 'memory' => 9]);
        }
        parent::__construct($stream, $options);
    }
}