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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteScope;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;

/**
 * Writer queue that runs each job inline and counts how many it ran.
 */
final class RecordingWriterQueue implements WriterQueueInterface
{
    public int $runs = 0;

    private WriteScope $scope;

    public function __construct()
    {
        $this->scope = new WriteScope();
    }

    public function run(Closure $job): void
    {
        $this->runs++;
        $this->scope->enter();

        try {
            $job();
        } finally {
            $this->scope->leave();
        }
    }

    public function isWriter(): bool
    {
        return $this->scope->isActive();
    }

    /**
     * Nothing is kept between jobs here, so there is nothing to release.
     */
    public function drain(): void {}
}
