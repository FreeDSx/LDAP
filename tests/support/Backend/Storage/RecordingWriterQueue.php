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

namespace Tests\Support\FreeDSx\Ldap\Backend\Storage;

use Closure;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;

/**
 * Writer queue that runs each job inline and counts how many it ran.
 */
final class RecordingWriterQueue implements WriterQueueInterface
{
    public int $runs = 0;

    public function run(Closure $job): void
    {
        $this->runs++;
        $job();
    }
}
