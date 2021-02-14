<?php

namespace SmaatCoda\EncryptedFilesystem;

use Illuminate\Filesystem\FilesystemManager;
use Illuminate\Support\ServiceProvider;
use League\Flysystem\Filesystem as Flysystem;
use SmaatCoda\EncryptedFilesystem\CipherMethods\OpenSslCipherMethod;

class EncryptedFilesystemServiceProvider extends ServiceProvider
{
    public function boot(FilesystemManager $filesystemManager)
    {
        $filesystemManager->extend('encrypted-filesystem', function ($app, $config) use ($filesystemManager) {
            $cipherMethod = $encryptionMethod = new OpenSslCipherMethod('io0GXLA0l3AmuZUPnEqB');
            $permissions = $config['permissions'] ?? [];

            $links = ($config['links'] ?? null) === 'skip'
                ? EncryptedFilesystemAdapter::SKIP_LINKS
                : EncryptedFilesystemAdapter::DISALLOW_LINKS;

            $adapter = new EncryptedFilesystemAdapter($cipherMethod, $config['root'], $config['lock'] ?? LOCK_EX, $links, $permissions);

            return new Flysystem($adapter, count($config) > 0 ? $config : null);
        });
    }
}