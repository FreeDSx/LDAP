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
use Throwable;

/**
 * Submits a closure to a single-threaded writer and blocks the caller until it completes.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface WriterQueueInterface
{
    /**
     * @throws Throwable
     */
    public function run(Closure $job): void;
}
