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
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;

/**
 * Write command DTO for an LDAP add operation.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class AddCommand implements WriteRequestInterface
{
    /**
     * @param list<Change> $systemChanges Stamped by the server, so they are applied after the caller's entry is validated.
     */
    public function __construct(
        public Entry $entry,
        public array $systemChanges = [],
    ) {}
}
