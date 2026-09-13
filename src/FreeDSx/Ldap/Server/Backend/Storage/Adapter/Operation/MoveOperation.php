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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;

/**
 * Builds the renamed/moved Entry, handling old-RDN removal and new-RDN attribute assignment.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class MoveOperation
{
    public function __construct(
        private RdnAttributeValues $rdnValues,
    ) {}

    public function execute(
        Entry $entry,
        MoveCommand $command,
    ): Entry {
        // The request may spell the entry's DN differently, so the old RDN and parent come from the stored one.
        $storedDn = $entry->getDn();
        $newEntry = new Entry(
            Dn::fromRdn(
                $command->newRdn,
                $command->newParent ?? $storedDn->getParent(),
            ),
            ...$entry->getAttributes(),
        );

        if ($command->deleteOldRdn) {
            $this->rdnValues->remove(
                $newEntry,
                $storedDn->getRdn(),
            );
        }
        $this->rdnValues->merge($newEntry);

        return $newEntry;
    }
}
