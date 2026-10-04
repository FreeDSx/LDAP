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

/**
 * Publishes the current metrics snapshot to a file so another process can read it (the PCNTL parent-to-child channel).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SnapshotPublisher
{
    public function __construct(
        private MetricsSnapshotProvider $source,
        private FileSnapshotWriter $writer,
    ) {}

    /**
     * @throws MetricsSnapshotException when the location cannot be readied.
     */
    public function prepare(): void
    {
        $this->writer->prepare();
    }

    public function publish(): void
    {
        $this->writer->write($this->source->snapshot());
    }

    public function remove(): void
    {
        $this->writer->remove();
    }
}
