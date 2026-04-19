<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock;

use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;

/**
 * PCNTL-safe lock: serializes writes on a sidecar `.lock` file and publishes updates atomically via rename().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class FileLock implements StorageLockInterface
{
    use AtomicStorageLockTrait;

    private const LOCK_SUFFIX = '.lock';

    /**
     * @var resource|null
     */
    private $lockHandle = null;

    private function acquireLock(): void
    {
        $handle = fopen(
            $this->filePath . self::LOCK_SUFFIX,
            'c',
        );

        if ($handle === false) {
            throw new StorageIoException('Unable to open the storage backend lock.');
        }

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);

            throw new StorageIoException('Unable to acquire exclusive lock on the storage backend.');
        }

        $this->lockHandle = $handle;
    }

    private function releaseLock(): void
    {
        if ($this->lockHandle === null) {
            return;
        }

        flock($this->lockHandle, LOCK_UN);
        fclose($this->lockHandle);
        $this->lockHandle = null;
    }

    private function readCurrentContents(): string
    {
        if (!file_exists($this->filePath)) {
            return '';
        }

        $contents = file_get_contents($this->filePath);

        if ($contents === false) {
            throw new StorageIoException('Unable to read the storage backend contents.');
        }

        return $contents;
    }

    private function writeContentsToTemp(
        string $tmpPath,
        string $contents,
    ): int {
        $bytesWritten = file_put_contents($tmpPath, $contents);

        if ($bytesWritten === false) {
            throw new StorageIoException('Unable to stage the storage update.');
        }

        return $bytesWritten;
    }
}
