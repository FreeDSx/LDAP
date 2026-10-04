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

use function basename;
use function dirname;
use function file_put_contents;
use function json_encode;
use function realpath;
use function rename;
use function sprintf;
use function tempnam;
use function unlink;

/**
 * Publishes a metrics snapshot to a file for another process to read.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileSnapshotWriter
{
    public function __construct(private SnapshotFile $file) {}

    /**
     * @throws MetricsSnapshotException when the location cannot be readied.
     */
    public function prepare(): void
    {
        $this->file->prepare();
    }

    /**
     * @throws MetricsSnapshotException when the snapshot cannot be published.
     */
    public function write(MetricsSnapshot $snapshot): void
    {
        $json = json_encode($snapshot->toArray());
        if ($json === false) {
            throw new MetricsSnapshotException('The metrics snapshot could not be encoded.');
        }

        $path = $this->file->path();
        $temporaryPath = $this->createTemporaryFileBeside($path);

        if (@file_put_contents($temporaryPath, $json) !== false && @rename($temporaryPath, $path)) {
            return;
        }
        @unlink($temporaryPath);

        throw new MetricsSnapshotException(sprintf(
            'The metrics snapshot could not be published at "%s".',
            $path,
        ));
    }

    public function remove(): void
    {
        $this->file->remove();
    }

    /**
     * The temporary file is created exclusively, so no other user can plant it first.
     *
     * @throws MetricsSnapshotException
     */
    private function createTemporaryFileBeside(string $path): string
    {
        // Compared resolved, since tempnam resolves symlinks in the path it returns.
        $directory = realpath(dirname($path));
        $temporaryPath = $directory === false
            ? false
            : @tempnam(
                $directory,
                basename($path) . '.',
            );

        // An unwritable directory makes tempnam fall back to the system temp directory, where a rename may not land.
        if ($temporaryPath !== false && dirname($temporaryPath) === $directory) {
            return $temporaryPath;
        }

        if ($temporaryPath !== false) {
            @unlink($temporaryPath);
        }

        throw new MetricsSnapshotException(sprintf(
            'The metrics snapshot could not be written beside "%s".',
            $path,
        ));
    }
}
