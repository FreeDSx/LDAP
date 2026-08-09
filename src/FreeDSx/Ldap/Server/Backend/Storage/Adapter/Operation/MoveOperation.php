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
use FreeDSx\Ldap\Entry\Rdn;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;

/**
 * Builds the renamed/moved Entry, handling old-RDN removal and new-RDN attribute assignment.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MoveOperation
{
    public function execute(
        Entry $entry,
        MoveCommand $command,
    ): Entry {
        $newDn = Dn::fromRdn(
            $command->newRdn,
            $command->newParent ?? $command->dn->getParent(),
        );
        $newEntry = new Entry($newDn, ...$entry->getAttributes());

        if ($command->deleteOldRdn) {
            foreach ($command->dn->getRdn()->getAll() as $component) {
                $newEntry->get($component->getName())?->removeValues(
                    [Rdn::unescape($component->getValue())],
                    caseSensitive: false,
                );
            }
        }

        return $newEntry->mergeRdnAttributes();
    }
}
