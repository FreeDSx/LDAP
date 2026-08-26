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

namespace FreeDSx\Ldap\Server\Backend\Write\Command;

use Closure;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;

/**
 * Write command DTO for a modify whose changes are derived from the entry as it stands under the write lock.
 *
 * Server-initiated only: the changes are a closure rather than data, so nothing can parse or replay one.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ComputeUpdateCommand implements WriteRequestInterface
{
    /**
     * @param Closure(Entry): list<Change> $compute Returning no changes leaves the entry untouched.
     */
    public function __construct(
        public Dn $dn,
        public Closure $compute,
    ) {}
}
