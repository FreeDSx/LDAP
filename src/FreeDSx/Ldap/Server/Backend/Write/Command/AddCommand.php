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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;

/**
 * Write command DTO for an LDAP add operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class AddCommand implements WriteRequestInterface
{
    public function __construct(readonly public Entry $entry)
    {
    }
}
