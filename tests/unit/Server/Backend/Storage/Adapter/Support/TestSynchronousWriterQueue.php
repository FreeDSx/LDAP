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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Storage\Adapter\Support;

use Closure;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;

/**
 * Test double that runs jobs synchronously on the calling thread.
 */
final class TestSynchronousWriterQueue implements WriterQueueInterface
{
    public int $ranCount = 0;

    /**
     * Jobs run on the caller here, so being inside one is all there is to being the writer.
     */
    private bool $running = false;

    public function run(Closure $job): void
    {
        $this->ranCount++;
        $wasRunning = $this->running;
        $this->running = true;

        try {
            $job();
        } finally {
            $this->running = $wasRunning;
        }
    }

    public function isWriter(): bool
    {
        return $this->running;
    }

    /**
     * Nothing is kept between jobs here, so there is nothing to release.
     */
    public function drain(): void {}
}
