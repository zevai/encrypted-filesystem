<?php


namespace SmaatCoda\EncryptedFilesystem\Encrypter;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\Stream;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use Psr\Http\Message\StreamInterface;
use function GuzzleHttp\Psr7\stream_for;

class EncryptingStream implements StreamInterface
{
    use StreamDecoratorTrait;

    const BLOCK_SIZE = 16;

    protected $stream;

    protected $key;

    protected $cipher;

    public function __construct($path, CipherInterface $cipher, $key)
    {
        $this->stream = Psr7\stream_for($path);
        $this->cipher = $cipher;
        $this->key    = $key;
    }

    public function read($length)
    {
        if ($length > strlen($this->buffer)) {
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_SIZE * ceil(($length - strlen($this->buffer)) / self::BLOCK_SIZE)
            );
        }
        $data         = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        return $data ? $data : '';
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }
        if ($whence === SEEK_SET) {
            $this->buffer = '';
            $wholeBlockOffset
                          = (int)($offset / self::BLOCK_SIZE) * self::BLOCK_SIZE;
            $this->stream->seek($wholeBlockOffset);
            $this->cipherMethod->seek($wholeBlockOffset);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    private function encryptBlock($length)
    {
        if ($this->stream->eof()) {
            return '';
        }

        $plainText = '';

        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        $options = OPENSSL_RAW_DATA;

        if (!$this->stream->eof() || $this->stream->getSize() !== $this->stream->tell()) {
            $options |= OPENSSL_ZERO_PADDING;
        }

        $cipherText = openssl_encrypt(
            $plainText,
            $this->cipher->getOpenSslName(),
            $this->key,
            $options,
            $this->cipher->getCurrentIv()
        );

        $this->cipher->update($cipherText);

        return $cipherText;
    }


}