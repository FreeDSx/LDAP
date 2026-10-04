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

namespace FreeDSx\Ldap\Server\Process\Child;

use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;

/**
 * A connection child that has exited, with the close reason it reported, if any.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ReapedChild
{
    public function __construct(
        public ChildProcess $process,
        public ?ConnectionObservation $closeReason = null,
    ) {}
}
