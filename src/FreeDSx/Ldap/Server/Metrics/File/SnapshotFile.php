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

namespace FreeDSx\Ldap\Server\Metrics\File;

use FreeDSx\Ldap\Exception\MetricsSnapshotException;

use function lstat;
use function posix_geteuid;
use function sprintf;
use function sys_get_temp_dir;
use function tempnam;
use function unlink;

/**
 * Where a metrics snapshot is published: a file created for this run in the temp directory, or a configured path.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SnapshotFile
{
    private const PREFIX = 'freedsx-ldap-monitor-';

    private function __construct(
        private ?string $path,
        private readonly ?int $owner = null,
    ) {}

    /**
     * The file is created exclusively by {@see prepare()}.
     */
    public static function inTempDirectory(): self
    {
        return new self(null);
    }

    /**
     * @param ?int $owner The user an existing file must belong to; null for the effective user.
     */
    public static function at(
        string $path,
        ?int $owner = null,
    ): self {
        return new self(
            $path,
            $owner,
        );
    }

    /**
     * @throws MetricsSnapshotException when a temp directory file has not been created yet.
     */
    public function path(): string
    {
        return $this->path ?? throw new MetricsSnapshotException('The metrics snapshot file has not been created.');
    }

    /**
     * Readies the location before anything is published to or read from it.
     *
     * @throws MetricsSnapshotException
     */
    public function prepare(): void
    {
        if ($this->path === null) {
            $this->path = $this->createInTempDirectory();

            return;
        }

        $this->assertNotOwnedByAnotherUser($this->path);
    }

    public function remove(): void
    {
        if ($this->path === null) {
            return;
        }

        @unlink($this->path);
    }

    /**
     * @throws MetricsSnapshotException
     */
    private function createInTempDirectory(): string
    {
        $path = @tempnam(
            sys_get_temp_dir(),
            self::PREFIX,
        );

        if ($path === false) {
            throw new MetricsSnapshotException('The metrics snapshot file could not be created in the temp directory.');
        }

        return $path;
    }

    /**
     * A file another user owns cannot be replaced in a sticky directory.
     *
     * @throws MetricsSnapshotException
     */
    private function assertNotOwnedByAnotherUser(string $path): void
    {
        $stat = @lstat($path);

        if ($stat === false || $stat['uid'] === ($this->owner ?? posix_geteuid())) {
            return;
        }

        throw new MetricsSnapshotException(sprintf(
            'The metrics snapshot at "%s" belongs to another user.',
            $path,
        ));
    }
}
