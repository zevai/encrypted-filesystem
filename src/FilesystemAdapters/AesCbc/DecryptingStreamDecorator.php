<?php

namespace SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc;

use GuzzleHttp\Psr7\StreamDecoratorTrait;
use LogicException;
use Psr\Http\Message\StreamInterface;
use SmaatCoda\EncryptedFilesystem\Interfaces\EncryptionMethodInterface;

class DecryptingStreamDecorator implements StreamInterface
{
    use StreamDecoratorTrait;

    protected $stream;

    protected $encryptor;

    protected $plaintextBuffer = '';

    protected $ciphertextBuffer = '';

    public function __construct(StreamInterface $stream, EncryptionMethodInterface $encryptor)
    {
        $this->stream = $stream;
        $this->encryptor = $encryptor;
    }

    public function seek($offset, $whence = SEEK_SET)
    {
        if ($whence === SEEK_CUR) {
            $offset = $this->tell() + $offset;
            $whence = SEEK_SET;
        }
        if ($whence === SEEK_SET) {
            $this->plaintextBuffer = '';

            $wholeBlockOffset = $this->encryptor->getBlockSize() * ceil($offset / $this->encryptor->getBlockSize());
            $this->encryptor->seek($wholeBlockOffset, $whence);
            $this->stream->seek($wholeBlockOffset, $whence);
            $this->read($offset - $wholeBlockOffset);
        } else {
            throw new LogicException('Unrecognized whence.');
        }
    }

    public function read($length): string
    {
        // FIXME: (the ciphertext buffer) for some reason, when the stream reads off last bytes, the eof
        //      continues to be false, until another reading occurs, which reads 0 bytes
        while (strlen($this->plaintextBuffer) < $length && !$this->stream->eof()) {
            $ciphertext = $this->readCiphertext(
//                $this->encryptor->getBlockSize() * ceil(($length - strlen($this->plaintextBuffer)) / $this->encryptor->getBlockSize())
                $this->encryptor->getBlockSize()
            );

            $this->plaintextBuffer .= $this->encryptor->decrypt($ciphertext, $this->stream->eof());
        }

        $data = substr($this->plaintextBuffer, 0, $length);
        $this->plaintextBuffer = substr($this->plaintextBuffer, $length);
        return $data;
    }

    public function eof()
    {
        return $this->stream->eof() && empty($this->plaintextBuffer);
    }

    public function getSize()
    {
        if ($this->encryptor->requiresPadding()) {
            return null;
        }

        return $this->stream->getSize();
    }

    public function isWritable()
    {
        return false;
    }

    private function readCiphertext($length)
    {
        if ($this->ciphertextBuffer === '' && $this->stream->eof()) {
            return '';
        }

        $ciphertext = $this->ciphertextBuffer;

        while (strlen($ciphertext) < $length && !$this->stream->eof()) {
            $ciphertext .= $this->stream->read($length - strlen($ciphertext));
        };

        $this->ciphertextBuffer = $this->stream->read($this->encryptor->getBlockSize());

        return $ciphertext;
    }
}
