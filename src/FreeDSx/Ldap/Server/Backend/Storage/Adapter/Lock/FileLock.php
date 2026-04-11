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

use FreeDSx\Ldap\Exception\RuntimeException;

/**
 * Locking strategy for the PCNTL server runner.
 *
 * Uses fopen + flock(LOCK_EX) to serialize concurrent writes across forked child processes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FileLock implements StorageLockInterface
{
    public function __construct(private readonly string $filePath)
    {
    }

    public function withLock(callable $mutation): void
    {
        $handle = fopen(
            $this->filePath,
            'c+'
        );

        if ($handle === false) {
            throw new RuntimeException(sprintf(
                'Unable to open storage file: %s',
                $this->filePath
            ));
        }

        if (!flock($handle, LOCK_EX)) {
            fclose($handle);

            throw new RuntimeException(sprintf(
                'Unable to acquire exclusive lock on storage file: %s',
                $this->filePath
            ));
        }

        try {
            $result = $mutation($this->readFromHandle($handle));

            $this->writeToHandle(
                $handle,
                $result
            );
        } finally {
            flock($handle, LOCK_UN);
            fclose($handle);
        }
    }

    /**
     * Read the raw file contents from an open file handle.
     *
     * @param resource $handle
     */
    private function readFromHandle(mixed $handle): string
    {
        $size = fstat($handle)['size'] ?? 0;

        if ($size <= 0) {
            return '';
        }

        $contents = fread(
            $handle,
            $size
        );

        return $contents !== false ? $contents : '';
    }

    /**
     * Write a string back to an open file handle, truncating first.
     *
     * @param resource $handle
     */
    private function writeToHandle(
        mixed $handle,
        string $contents,
    ): void {
        ftruncate($handle, 0);
        rewind($handle);
        fwrite($handle, $contents);
    }
}
