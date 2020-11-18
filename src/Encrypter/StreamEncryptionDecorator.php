<?php


namespace SmaatCoda\EncryptedFilesystem\Encrypter;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;
use SmaatCoda\EncryptedFilesystem\Encrypter\EncryptionMethods\EncryptionMethodInterface;

class StreamEncryptionDecorator implements StreamInterface
{
    use StreamDecoratorTrait;

    const BLOCK_LENGTH = 16;

    protected $stream;

    protected $key;

    protected $encryptionMethod;

    protected $buffer;

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
            $this->buffer = '';
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
        // TODO: when a file is only one block in size, the encryptor reaches eof while the only returning the iv, the actual data being in the buffer
        if ($length > strlen($this->buffer)) {
            $this->buffer .= $this->encryptBlock(
                self::BLOCK_LENGTH * ceil(($length - strlen($this->buffer)) / self::BLOCK_LENGTH)
            );
        }
        $data = substr($this->buffer, 0, $length);
        $this->buffer = substr($this->buffer, $length);
        return $data ?: '';
    }

    public function getSize()
    {
        $originalSize = $this->stream->getSize();

        if ($originalSize !== null && $this->encryptionMethod->requiresPadding()) {
            return $originalSize + self::BLOCK_LENGTH - $originalSize % self::BLOCK_LENGTH;
        }

        return $originalSize;
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

        $options = OPENSSL_RAW_DATA;


        if (!$this->stream->eof() && $this->stream->getSize() !== $this->stream->tell()) {
            $options |= OPENSSL_ZERO_PADDING;
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
