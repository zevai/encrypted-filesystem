<?php


namespace SmaatCoda\EncryptedFilesystem\CipherMethods;

use Closure;
use SmaatCoda\EncryptedFilesystem\Exceptions\InvalidCipherMethod;
use SmaatCoda\EncryptedFilesystem\Exceptions\InvalidConfiguration;
use SmaatCoda\EncryptedFilesystem\Exceptions\UnregisteredCipherMethod;
use SmaatCoda\EncryptedFilesystem\Interfaces\CipherMethodInterface;

class CipherMethodFactory
{

    protected static $resolvers = [];

    public static function make(array $config)
    {
        if (isset(static::$resolvers[$config['cipher-method']])) {
            $cipherMethod = call_user_func(static::$resolvers[$config['cipher-method']], $config);
            if ($cipherMethod instanceof CipherMethodInterface) {
                return $cipherMethod;
            }

            throw new InvalidCipherMethod($config['cipher-method']);
        }

        switch ($config['cipher-method']) {
            case 'aes-256-cbc':
                return new OpenSslCipherMethod($config['key'], $config['cipher-method']);
            default:
                throw new UnregisteredCipherMethod($config['cipher-method']);
        }
    }

    public static function registerResolver(string $cipherMethod, Closure $resolver)
    {
        self::$resolvers[$cipherMethod] = $resolver;
    }
}