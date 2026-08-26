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
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;

/**
 * Write command DTO for an LDAP modifyDn (rename/move) operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MoveCommand implements WriteRequestInterface
{
    public function __construct(
        public Dn $dn,
        public Rdn $newRdn,
        public bool $deleteOldRdn,
        public ?Dn $newParent,
    ) {}
}
