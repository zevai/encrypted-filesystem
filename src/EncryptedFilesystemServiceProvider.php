<?php

namespace SmaatCoda\EncryptedFilesystem;

use Illuminate\Filesystem\FilesystemManager;
use Illuminate\Support\ServiceProvider;
use League\Flysystem\Filesystem as Flysystem;
use SmaatCoda\EncryptedFilesystem\CipherMethods\OpenSslCipherMethod;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\EncryptedLocalAdapter;
use SmaatCoda\EncryptedFilesystem\FilesystemAdapters\FilesystemAdapter;

class EncryptedFilesystemServiceProvider extends ServiceProvider
{
    public function boot(FilesystemManager $filesystemManager)
    {
        $filesystemManager->extend('encrypted-filesystem', function ($app, $config) use ($filesystemManager) {
            $cipherMethod = $encryptionMethod = new OpenSslCipherMethod($config['key']);
            $permissions = $config['permissions'] ?? [];

            $links = ($config['links'] ?? null) === 'skip'
                ? EncryptedLocalAdapter::SKIP_LINKS
                : EncryptedLocalAdapter::DISALLOW_LINKS;

            $adapter = new EncryptedLocalAdapter($cipherMethod, $config['root'], $config['lock'] ?? LOCK_EX, $links, $permissions);

            return new FilesystemAdapter(new Flysystem($adapter, count($config) > 0 ? $config : null));
        });
    }
}