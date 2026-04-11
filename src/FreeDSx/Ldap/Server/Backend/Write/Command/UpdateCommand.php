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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;

/**
 * Write command DTO for an LDAP modify operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class UpdateCommand implements WriteRequestInterface
{
    /**
     * @param Change[] $changes
     */
    public function __construct(
        readonly public Dn $dn,
        readonly public array $changes,
    ) {
    }
}
