## Encrypted Filesystem
#### About
**Encrypted Filesystem** enables easy encryption and decryption of the files in a Laravel Application.
Encryption and decryption is done using streams, which prevents unencrypted files from ever being stored on the disk. 

#### How to install
To install **Encrypted Filesystem** run:

`composer require smaatcoda/encrypted-filesystem`

After the package is installed, register Encrypted Filesystem Service Provider in your `app.php` config file:

```
'providers' => [

    ...

    SmaatCoda\EncryptedFilesystem\EncryptedFilesystemServiceProvider::class,
],

```

In order to start using the package you have to add a new filesystem configuration.
In your `filesystems.php` add a new entry to the `disks` array which contains the following parameters:

```
'example-encrypted-disk-name' => [
    'driver' => 'encrypted-filesystem',
    'root' => storage_path('app'),
    'key' => 'example-key',
    'cipher-method' => 'aes-256-cbc',
],
``` 

Now you can use Laravel's `Storage` and either reference your encrypted disk explicitly:

`Storage::disk('example-encrypted-disk-name')->put('example.txt', 'Contents');`

or make your encrypted disk the default one in `filesystems.php` and simply do:

`Storage::put('example.txt', 'Contents');`