<?php

namespace SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc;

use GuzzleHttp\Psr7;
use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\EncryptionMethodInterface;

class DecryptingStreamDecorator implements StreamInterface
{
    use StreamDecoratorTrait;

    const BLOCK_LENGTH = 16;

    protected $stream;

    protected $key;

    protected $encryptionMethod;

    protected $decryptionBuffer = '';

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
            $this->decryptionBuffer = '';
            $wholeBlockOffset = (int)($offset / self::BLOCK_LENGTH) * self::BLOCK_LENGTH;
            $this->stream->seek($wholeBlockOffset);
            $this->encryptionMethod->seek($wholeBlockOffset);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    public function read($length)
    {
        if ($length > strlen($this->decryptionBuffer)) {
            $this->decryptionBuffer .= $this->decryptBlock(
                self::BLOCK_LENGTH * ceil(($length - strlen($this->decryptionBuffer)) / self::BLOCK_LENGTH)
            );
        }
        $data = substr($this->decryptionBuffer, 0, $length);

        $this->decryptionBuffer = substr($this->decryptionBuffer, $length);
        return $data ? $data : '';
    }

    public function getSize()
    {
        if ($this->encryptionMethod->requiresPadding()) {
            return null;
        }

        return $this->stream->getSize();
    }

    public function isWritable()
    {
        return false;
    }

    private function decryptBlock($length)
    {
        if ($this->encryptionBuffer === '' && $this->stream->eof()) {
            return '';
        }

        $encryptedText = $this->encryptionBuffer;

        while (strlen($encryptedText) < $length && !$this->stream->eof()) {
            $encryptedText .= $this->stream->read($length - strlen($encryptedText));
        };

        $this->encryptionBuffer = $this->stream->read(self::BLOCK_LENGTH);

        $options = OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING;
        if ($this->encryptionBuffer === '' || $this->stream->eof()) {
            $options = OPENSSL_RAW_DATA;
        }

        $decryptedText = openssl_decrypt(
            $encryptedText,
            $this->encryptionMethod->getOpenSslMethod(),
            $this->key,
            $options,
            $this->encryptionMethod->getCurrentIv()
        );

        $this->encryptionMethod->update($encryptedText);

        return $decryptedText;
    }
}
