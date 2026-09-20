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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Writer;

use Closure;

/**
 * Runs each write in place on the caller, for when writes are not serialized through a single writer.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ImmediateWriterQueue implements WriterQueueInterface
{
    public function run(Closure $job): mixed
    {
        return $job();
    }

    public function isWriter(): bool
    {
        return false;
    }

    public function drain(): void {}
}
