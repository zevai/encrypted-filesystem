<?php


namespace SmaatCoda\EncryptedFilesystem\CompressionMethods\Zlib;


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

        $config = ['level' => 9, 'window' => 15, 'memory' => 9];

        if (isset($options['direction']) && $options['direction'] == self::DIRECTION_WRITE) {
            stream_filter_append($stream, 'zlib.deflate', STREAM_FILTER_WRITE, $config);
            stream_filter_append($stream, 'zlib.inflate', STREAM_FILTER_READ, $config);
        } else {
            stream_filter_append($stream, 'zlib.deflate', STREAM_FILTER_READ, $config);
            stream_filter_append($stream, 'zlib.inflate', STREAM_FILTER_WRITE, $config);
        }

        parent::__construct($stream, $options);
    }
}