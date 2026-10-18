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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation\Linked;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

use function array_filter;
use function array_values;

/**
 * Separates the linked values a modify changes from the changes its entry is still stored whole for.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class LinkedChanges
{
    public function __construct(private LinkedAttributes $linked) {}

    /**
     * The linked changes applied apart from the entry, or none when the modify has to be applied to the whole entry.
     *
     * @return list<Change>
     */
    public function changesApart(
        UpdateCommand $command,
        WriteContext $context,
    ): array {
        // A control reading the entry needs every value it holds, which only the whole-entry path materializes.
        if ($this->linked->isEmpty() || $context->controlEvaluator()?->inspectsEntry() === true) {
            return [];
        }
        $apart = [];

        foreach ($command->changes as $change) {
            if (!$this->linked->links($change->getAttribute())) {
                continue;
            }

            // One change the attribute has to be written whole for settles it for every value of that attribute.
            if (!$this->isApplicable($change, $command->dn)) {
                return [];
            }

            $apart[] = $change;
        }

        return $apart;
    }

    /**
     * The command without the changes applied apart, which is what the entry is still stored for.
     *
     * @param list<Change> $apart
     */
    public function remaining(
        UpdateCommand $command,
        array $apart,
    ): UpdateCommand {
        if ($apart === []) {
            return $command;
        }

        return new UpdateCommand(
            $command->dn,
            array_values(array_filter(
                $command->changes,
                fn(Change $change): bool => !$this->linked->links($change->getAttribute()),
            )),
            $command->systemChanges,
        );
    }

    /**
     * Whether the change names the values it changes, rather than restating what the attribute holds.
     */
    private function isApplicable(
        Change $change,
        Dn $dn,
    ): bool {
        // Naming the entry, so the attribute is held to the RDN it spells rather than changed on its own.
        if ($dn->getRdn()->has($change->getAttribute()->getName())) {
            return false;
        }

        if ($change->isAdd()) {
            return $change->getAttribute()->getValues() !== [];
        }

        // A delete naming no value empties the attribute, which takes knowing everything it holds.
        return $change->isDelete() && !$change->isReset();
    }
}
