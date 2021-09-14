<?php

namespace SmaatCoda\EncryptedFilesystem\FilesystemAdapters;

use GuzzleHttp\Psr7\MimeType;
use Illuminate\Filesystem\FilesystemAdapter as BaseFilesystemAdapter;
use Psr\Http\Message\StreamInterface;
use Symfony\Component\HttpFoundation\StreamedResponse;

/**
 * @mixin \League\Flysystem\FilesystemInterface
 */
class FilesystemAdapter extends BaseFilesystemAdapter
{
    /** @inheritdoc  */
    public function response($path, $name = null, array $headers = [], $disposition = 'inline')
    {
        $response = new StreamedResponse;

        $filename = $name ?? basename($path);

        $disposition = $response->headers->makeDisposition(
            $disposition, $filename, $this->fallbackName($filename)
        );

        $response->headers->replace($headers + [
                'Content-Type' => MimeType::fromFilename($name),
                'Content-Disposition' => $disposition,
            ]);

        $response->setCallback(function () use ($path) {
            /** @var resource|StreamInterface $stream */
            $stream = $this->readStream($path);
            if (is_resource($stream)) {
                fpassthru($stream);
                fclose($stream);
            } else if ($stream instanceof StreamInterface) {
                while (!$stream->eof()) {
                    echo $stream->read(16);
                }

                $stream->close();
            }
        });

        return $response;
    }


}