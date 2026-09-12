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
use FreeDSx\Ldap\Server\Metrics\MetricsSnapshotProvider;
use FreeDSx\Ldap\Server\Metrics\Snapshot\MetricsSnapshot;

use function file_get_contents;
use function is_array;
use function json_decode;
use function sprintf;

/**
 * Reads a metrics snapshot another process published to a file.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class FileSnapshotProvider implements MetricsSnapshotProvider
{
    public function __construct(private string $path) {}

    /**
     * @throws MetricsSnapshotException when no snapshot can be read.
     */
    public function snapshot(): MetricsSnapshot
    {
        $contents = @file_get_contents($this->path);

        if ($contents === false) {
            throw new MetricsSnapshotException(sprintf(
                'The metrics snapshot at "%s" could not be read.',
                $this->path,
            ));
        }
        $data = json_decode(
            $contents,
            true,
        );
        if (!is_array($data)) {
            throw new MetricsSnapshotException(sprintf(
                'The metrics snapshot at "%s" could not be decoded.',
                $this->path,
            ));
        }

        return MetricsSnapshot::fromArray($data);
    }
}
