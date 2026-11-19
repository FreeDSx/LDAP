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

namespace FreeDSx\Ldap\Sync\Consumer\Checkpoint;

use FreeDSx\Ldap\Exception\RuntimeException;

use function file_get_contents;
use function file_put_contents;
use function is_file;
use function rename;
use function sprintf;
use function unlink;

use const LOCK_EX;

/**
 * Stores the sync cookie in a file, replaced atomically via a temp file and rename.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileReplicationCheckpoint implements ReplicationCheckpointInterface
{
    public function __construct(private string $path) {}

    public function read(): ?string
    {
        if (!is_file($this->path)) {
            return null;
        }

        $cookie = @file_get_contents($this->path);

        if ($cookie === false) {
            throw new RuntimeException(sprintf(
                'Unable to read the replication checkpoint at "%s".',
                $this->path,
            ));
        }

        return $cookie;
    }

    public function write(string $cookie): void
    {
        $tmp = $this->path . '.tmp';

        $written = @file_put_contents(
            $tmp,
            $cookie,
            LOCK_EX,
        );

        if ($written === false) {
            throw new RuntimeException(sprintf(
                'Unable to write the replication checkpoint to "%s".',
                $tmp,
            ));
        }

        if (!@rename($tmp, $this->path)) {
            @unlink($tmp);

            throw new RuntimeException(sprintf(
                'Unable to move the replication checkpoint into place at "%s".',
                $this->path,
            ));
        }
    }

    public function clear(): void
    {
        if (!is_file($this->path)) {
            return;
        }

        if (!@unlink($this->path)) {
            throw new RuntimeException(sprintf(
                'Unable to remove the replication checkpoint at "%s".',
                $this->path,
            ));
        }
    }
}
