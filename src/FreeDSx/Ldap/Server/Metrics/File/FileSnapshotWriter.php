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
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;

use function file_put_contents;
use function getmypid;
use function json_encode;
use function rename;
use function sprintf;
use function unlink;

/**
 * Publishes a metrics snapshot to a file for another process to read.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileSnapshotWriter
{
    public function __construct(private string $path) {}

    /**
     * @throws MetricsSnapshotException when the snapshot cannot be published.
     */
    public function write(MetricsSnapshot $snapshot): void
    {
        $json = json_encode($snapshot->toArray());
        if ($json === false) {
            throw new MetricsSnapshotException('The metrics snapshot could not be encoded.');
        }

        $temporaryPath = $this->path . '.' . getmypid() . '.tmp';

        if (@file_put_contents($temporaryPath, $json) === false) {
            throw new MetricsSnapshotException(sprintf(
                'The metrics snapshot could not be written to "%s".',
                $temporaryPath,
            ));
        }
        if (@rename($temporaryPath, $this->path)) {
            return;
        }
        @unlink($temporaryPath);

        throw new MetricsSnapshotException(sprintf(
            'The metrics snapshot could not be moved into place at "%s".',
            $this->path,
        ));
    }

    public function remove(): void
    {
        @unlink($this->path);
    }
}
