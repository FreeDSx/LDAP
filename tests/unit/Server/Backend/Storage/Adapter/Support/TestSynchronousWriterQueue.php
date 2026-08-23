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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriteScope;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer\WriterQueueInterface;

/**
 * Test double that runs jobs synchronously on the calling thread.
 */
final class TestSynchronousWriterQueue implements WriterQueueInterface
{
    public int $ranCount = 0;

    private WriteScope $scope;

    public function __construct()
    {
        $this->scope = new WriteScope();
    }

    public function run(Closure $job): void
    {
        $this->ranCount++;
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
