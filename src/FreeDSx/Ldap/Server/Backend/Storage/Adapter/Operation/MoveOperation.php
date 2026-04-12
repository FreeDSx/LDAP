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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;

/**
 * Constructs a new Entry from the given RDN / parent, handling old RDN
 * deletion and new RDN attribute assignment.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class MoveOperation
{
    public function execute(
        Entry $entry,
        MoveCommand $command,
    ): Entry {
        $parent = $command->newParent ?? $command->dn->getParent();
        $newDnString = $parent !== null
            ? $command->newRdn->toString() . ',' . $parent->toString()
            : $command->newRdn->toString();

        $newDn = new Dn($newDnString);
        $newEntry = new Entry($newDn, ...$entry->getAttributes());

        if ($command->deleteOldRdn) {
            foreach ($command->dn->getRdn()->getAll() as $component) {
                $newEntry->get($component->getName())?->removeValues(
                    [$component->getValue()],
                    caseSensitive: false,
                );
            }
        }

        foreach ($command->newRdn->getAll() as $component) {
            $existing = $newEntry->get($component->getName());
            if ($existing === null) {
                $newEntry->set(new Attribute($component->getName(), $component->getValue()));

                continue;
            }
            if (!$existing->has($component->getValue(), caseSensitive: false)) {
                $existing->add($component->getValue());
            }
        }

        return $newEntry;
    }
}
