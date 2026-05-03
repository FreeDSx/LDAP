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

    public function run(Closure $job): void
    {
        $this->ranCount++;
        $job();
    }
}
