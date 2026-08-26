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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;

/**
 * Write command DTO for a delete that takes everything beneath the entry with it.
 *
 * Deliberately not a DeleteCommand, so a dispatcher matching on type can never mistake one for the other.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class DeleteSubtreeCommand implements WriteRequestInterface
{
    public function __construct(public Dn $dn) {}
}
