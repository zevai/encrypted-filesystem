<?php


namespace SmaatCoda\EncryptedFilesystem\Tests;

use Orchestra\Testbench\TestCase as BaseTestCase;
use SmaatCoda\EncryptedFilesystem\CipherMethods\OpenSslCipherMethod;
use SmaatCoda\EncryptedFilesystem\EncryptedFilesystemServiceProvider;

class TestCase extends BaseTestCase
{
    protected function getPackageProviders($app)
    {
        return [EncryptedFilesystemServiceProvider::class];
    }

    protected function getEnvironmentSetUp($app)
    {
        $app['config']->set('filesystems.default', 'encrypted-disk');
        $app['config']->set('filesystems.disks.encrypted-disk', [
            'key' => 'io0GXLA0l3AmuZUPnEqB',
            'cipher-method' => OpenSslCipherMethod::AES_256_CBC,
            'driver' => 'encrypted-filesystem',
            'root' => dirname(__DIR__) . '/storage',
        ]);
    }

}