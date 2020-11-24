<?php


namespace SmaatCoda\EncryptedFilesystem\FilesystemAdapters\AesCbc;


class FilesystemAdapter
{
    /**
     * Define the number of blocks that should be read from the source file for each chunk.
     * We chose 255 because on decryption we want to read chunks of 4kb ((255 + 1)*16).
     */
    const FILE_ENCRYPTION_BLOCKS = 255;

    /**
     * This extension is attributed to encrypted files and will be checked for before decryption
     */
    const FILENAME_POSTFIX = '.enc';

    /**
     * Adapter name
     */
    const ADAPTER_NAME = 'encrypted';

    /**
     * The encryption key.
     *
     * @var string
     */
    protected $key;

    /**
     * The algorithm used for encryption.
     *
     * @var string
     */
    protected $cipher;

    /**
     * EncryptedAdapter constructor.
     * @param $root
     * @param int $writeFlags
     * @param int $linkHandling
     * @param array $permissions
     */
    public function __construct(
        $root,
        $writeFlags = LOCK_EX,
        $linkHandling = self::DISALLOW_LINKS,
        array $permissions = []
    )
    {
        $this->key = env('APP_KEY');
        $this->cipher = 'AES-256-CBC';

        parent::__construct($root, $writeFlags, $linkHandling, $permissions);
    }


    /**
     * @param string $destPath
     * @param string $contents
     * @param Config $config
     * @return array|bool|false
     * @throws Exception
     */
    public function write($destPath, $contents, Config $config)
    {

        try {
            if ($contents instanceof UploadedFile) {
                $sourceRealPath = realpath($contents);
            } else {
                $tmpFile = tmpfile();
                fwrite($tmpFile, $contents);
                $sourceRealPath = stream_get_meta_data($tmpFile)['uri'];
            }
        } catch (Exception $exception) {
            Log::error('Could not get file real path. Error: ' . $exception->getMessage());
            return false;
        }

        $destRealPath = $this->attachEncryptionMarkers($this->applyPathPrefix($destPath));
        $this->ensureDirectory(dirname($destRealPath));

        try {
            $this->encrypt($sourceRealPath, $destRealPath);
        } catch (Exception $exception) {
            Log::error('Could not encrypt file. Error: ' . $exception->getMessage());
            return false;
        }

        return true;
    }

    /**
     * @param string $destPath
     * @param string $contents
     * @param Config $config
     * @return array|bool|false
     * @throws Exception
     */
    public function update($destPath, $contents, Config $config)
    {
        return $this->write($destPath, $contents, $config);
    }

    /**
     * @param string $path
     * @return array|bool|false
     * @throws Exception
     */
    public function read($path)
    {
        $destRealPath = $this->applyPathPrefix($path);
        $sourceRealPath = $this->attachEncryptionMarkers($this->applyPathPrefix($path));

        // Only try to decrypt a previously encrypted file
        $this->decrypt($sourceRealPath, $destRealPath);
        $contents = @file_get_contents($destRealPath);
        unlink($destRealPath);

        return ['type' => 'file', 'contents' => $contents];
    }

    /**
     * @param $path
     * @param null $filename
     * @return \Illuminate\Contracts\Routing\ResponseFactory|\Symfony\Component\HttpFoundation\Response
     * @throws FileNotFoundException
     */
    public function download($path, $filename = null)
    {
        if (!$this->has($path)) {
            throw new FileNotFoundException($path);
        }

        $contents = $this->read($path)['contents'];
        $filename = $filename ? $filename : basename($path);

        if ($contents === false) {
            throw new FileNotFoundException($path);
        }

        return response($contents, 200, [
            'Content-Disposition' => 'attachment; filename="' . $filename . '"',
        ]);
    }

    /**
     * @inheritdoc
     */
    public function rename($path, $newpath)
    {
        return parent::rename($this->attachEncryptionMarkers($path), $this->attachEncryptionMarkers($newpath));
    }

    /**
     * @inheritdoc
     */
    public function copy($path, $newpath)
    {
        return parent::copy($this->attachEncryptionMarkers($path), $this->attachEncryptionMarkers($newpath));
    }

    /**
     * @inheritdoc
     */
    public function delete($path)
    {
        return parent::delete($this->attachEncryptionMarkers($path));
    }

    /**
     * @param string $path
     * @return array|bool|null
     */
    public function has($path)
    {
        return parent::has($this->attachEncryptionMarkers($path));
    }

    /**
     * @param string $path
     * @param resource $resource
     * @param Config $config
     * @return array|bool|false|void
     */
    public function writeStream($path, $resource, Config $config)
    {
        //TODO: implement encryption for stream operations
        throw new \BadMethodCallException('Operations on stream are not allowed for EncryptedFilesystem driver!');
    }

    /**
     * @param string $path
     * @return array|false
     * @throws Exception
     */
    public function readStream($path)
    {
        $sourceRealPath = $this->attachEncryptionMarkers($this->applyPathPrefix($path));
        $destRealPath = 'php://output';

        $this->decrypt($sourceRealPath, $destRealPath);

        $stream = fopen($destRealPath, 'rb');

        return ['type' => 'file', 'path' => $destRealPath, 'stream' => $stream];
    }

    /**
     * @param string $path
     * @param resource $resource
     * @param Config $config
     * @return array|bool|false|void
     */
    public function updateStream($path, $resource, Config $config)
    {
        //TODO: implement encryption for stream operations
        throw new \BadMethodCallException('Operations on stream are not allowed for EncryptedFilesystem driver!');
    }

    /**
     * @param $key
     * @param $cipher
     * @return bool
     */
    public static function supported($key, $cipher)
    {
        $length = mb_strlen($key, '8bit');

        return ($cipher === 'AES-128-CBC' && $length === 16) ||
            ($cipher === 'AES-256-CBC' && $length === 32);
    }

    /**
     * @param $sourcePath
     * @param $destPath
     * @return bool
     * @throws Exception
     */
    public function encrypt($sourcePath, $destPath)
    {
        $fpOut = $this->openDestFile($destPath);
        $fpIn = $this->openSourceFile($sourcePath);
        // Put the initialzation vector to the beginning of the file
        $iv = openssl_random_pseudo_bytes(16);
        fwrite($fpOut, $iv);
        $numberOfChunks = ceil(filesize($sourcePath) / (16 * self::FILE_ENCRYPTION_BLOCKS));
        $i = 0;
        while (!feof($fpIn)) {
            $plaintext = fread($fpIn, 16 * self::FILE_ENCRYPTION_BLOCKS);
            $ciphertext = openssl_encrypt($plaintext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);
            // Because Amazon S3 will randomly return smaller sized chunks:
            // Check if the size read from the stream is different than the requested chunk size
            // In this scenario, request the chunk again, unless this is the last chunk
            if (strlen($plaintext) !== 16 * self::FILE_ENCRYPTION_BLOCKS
                && $i + 1 < $numberOfChunks
            ) {
                fseek($fpIn, 16 * self::FILE_ENCRYPTION_BLOCKS * $i);
                continue;
            }
            // Use the first 16 bytes of the ciphertext as the next initialization vector
            $iv = substr($ciphertext, 0, 16);
            fwrite($fpOut, $ciphertext);
            $i++;
        }

        fclose($fpIn);
        fclose($fpOut);

        return true;
    }

    /**
     * @param $sourcePath
     * @param $destPath
     * @return bool
     * @throws Exception
     */
    public function decrypt($sourcePath, $destPath)
    {
        $fpOut = $this->openDestFile($destPath);
        $fpIn = $this->openSourceFile($sourcePath);
        // Get the initialization vector from the beginning of the file
        $iv = fread($fpIn, 16);
        $numberOfChunks = ceil((filesize($sourcePath) - 16) / (16 * (self::FILE_ENCRYPTION_BLOCKS + 1)));
        $i = 0;
        while (!feof($fpIn)) {
            // We have to read one block more for decrypting than for encrypting because of the initialization vector
            $ciphertext = fread($fpIn, 16 * (self::FILE_ENCRYPTION_BLOCKS + 1));
            $plaintext = openssl_decrypt($ciphertext, $this->cipher, $this->key, OPENSSL_RAW_DATA, $iv);
            // Because Amazon S3 will randomly return smaller sized chunks:
            // Check if the size read from the stream is different than the requested chunk size
            // In this scenario, request the chunk again, unless this is the last chunk
            if (strlen($ciphertext) !== 16 * (self::FILE_ENCRYPTION_BLOCKS + 1)
                && $i + 1 < $numberOfChunks
            ) {
                fseek($fpIn, 16 + 16 * (self::FILE_ENCRYPTION_BLOCKS + 1) * $i);
                continue;
            }
            if ($plaintext === false) {
                throw new Exception('Decryption failed');
            }
            // Get the the first 16 bytes of the ciphertext as the next initialization vector
            $iv = substr($ciphertext, 0, 16);
            fwrite($fpOut, $plaintext);
            $i++;
        }

        fclose($fpIn);
        fclose($fpOut);

        return true;
    }

    /**
     * @param $destPath
     * @return false|resource
     * @throws Exception
     */
    protected function openDestFile($destPath)
    {
        if (!is_dir(dirname($destPath))) {
            if (!mkdir($concurrentDirectory = dirname($destPath), 0777, true) && !is_dir($concurrentDirectory)) {
                throw new \RuntimeException(sprintf('Directory "%s" was not created', $concurrentDirectory));
            }
        }

        if (($fpOut = fopen($destPath, 'w')) === false) {
            throw new Exception('Cannot open file for writing');
        }

        return $fpOut;
    }

    /**
     * @param $sourcePath
     * @return false|resource
     * @throws Exception
     */
    protected function openSourceFile($sourcePath)
    {
        $contextOpts = Str::startsWith($sourcePath, 's3://') ? ['s3' => ['seekable' => true]] : [];
        if (($fpIn = fopen($sourcePath, 'r', false, stream_context_create($contextOpts))) === false) {
            throw new Exception('Cannot open file for reading');
        }

        return $fpIn;
    }

    /**
     * @param $destPath
     * @return string
     */
    protected function attachEncryptionMarkers($destPath)
    {
        return $destPath . self::FILENAME_POSTFIX;
    }

    /**
     * @param $sourceRealPath
     * @return string|string[]|null
     */
    protected function detachEncryptionMarkers($sourceRealPath)
    {
        return preg_replace('/(' . self::FILENAME_POSTFIX . ')$/', '', $sourceRealPath);
    }

}