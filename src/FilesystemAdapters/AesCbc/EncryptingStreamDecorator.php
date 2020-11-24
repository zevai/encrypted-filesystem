<?php


namespace SmaatCoda\EncryptedFilesystem\Interfaces;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\EncryptionMethods\EncryptionMethodInterface;

class EncryptingStreamDecorator implements StreamInterface
{
    use StreamDecoratorTrait;

    const BLOCK_LENGTH = 16;

    protected $stream;

    protected $key;

    protected $encryptionMethod;

    protected $encryptionBuffer = '';

    public function __construct(StreamInterface $stream, EncryptionMethodInterface $encryptionMethod, $key)
    {
        $this->stream = $stream;
        $this->encryptionMethod = $encryptionMethod;
        $this->key = $key;
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }
        if ($whence === SEEK_SET) {
            $this->encryptionBuffer = '';
            $wholeBlockOffset
                = (int)($offset / self::BLOCK_LENGTH) * self::BLOCK_LENGTH;
            $this->stream->seek($wholeBlockOffset);
            $this->encryptionMethod->seek($wholeBlockOffset);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    public function read($length)
    {
        if ($length > strlen($this->encryptionBuffer)) {
            $this->encryptionBuffer .= $this->encryptBlock(
                self::BLOCK_LENGTH * ceil(($length - strlen($this->encryptionBuffer)) / self::BLOCK_LENGTH)
            );
        }
        $data = substr($this->encryptionBuffer, 0, $length);
        $this->encryptionBuffer = substr($this->encryptionBuffer, $length);
        return $data ?: '';
    }

    public function eof()
    {
        return $this->stream->eof() && empty($this->encryptionBuffer);
    }

    public function getSize()
    {
        $originalSize = $this->stream->getSize();
        $requiresPadding = $this->encryptionMethod->requiresPadding();

        $finalSize = $originalSize;

        if ($originalSize !== null && $requiresPadding) {
            $finalSize += self::BLOCK_LENGTH - $originalSize % self::BLOCK_LENGTH;
        }

        // Add the IV bytes
        $finalSize += self::BLOCK_LENGTH;

        return $finalSize;
    }

    public function isWritable()
    {
        return false;
    }

    private function encryptBlock($length)
    {
        if ($this->stream->eof()) {
            return '';
        }

        $prefix = '';
        $plainText = '';

        if ($this->stream->tell() == 0) {
            $prefix = $this->encryptionMethod->getCurrentIv();
        }

        do {
            $plainText .= $this->stream->read($length - strlen($plainText));
        } while (strlen($plainText) < $length && !$this->stream->eof());

        // Don't know why bitwise operator is required
        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;

        if ($this->stream->eof()) {
            $options = OPENSSL_RAW_DATA;
        }

        $encryptedText = openssl_encrypt(
            $plainText,
            $this->encryptionMethod->getOpenSslMethod(),
            $this->key,
            $options,
            $this->encryptionMethod->getCurrentIv()
        );

        $this->encryptionMethod->update($encryptedText);
        $encryptedText = $prefix . $encryptedText;

        return $encryptedText;
    }
}
