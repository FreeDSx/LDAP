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

namespace FreeDSx\Ldap\Server\Backend\Write\Operation;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\RdnAttributeValues;
use FreeDSx\Ldap\Server\Backend\Write\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationGate;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Creates an entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AddEntryHandler
{
    use AppliesSystemChanges;

    public function __construct(
        private TransactionalEntryWrite $writes,
        private EntryPlacementGuard $placement,
        private SchemaViolationGate $schemaGate,
        private OperationalAttributeGenerator $operationalAttrs,
        private RdnAttributeValues $rdnValues,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        AddCommand $command,
        WriteContext $context,
    ): void {
        $bulkLoad = $context->bulkLoadOptions();

        $this->writes->add(
            $context,
            fn(): Entry => $this->prepared(
                $command,
                $context,
            ),
            replaceExisting: $bulkLoad !== null && $bulkLoad->replaceExisting,
        );
    }

    /**
     * @throws OperationException
     */
    private function prepared(
        AddCommand $command,
        WriteContext $context,
    ): Entry {
        // Worked on a copy, so a retried attempt never sees what an earlier one merged or stamped.
        $entry = $command->entry->makeCopy();
        // Merged before validation, so the values naming the entry count toward what its object classes require.
        $this->rdnValues->merge($entry);

        $bulkLoad = $context->bulkLoadOptions();

        $this->schemaGate->assertAddAllowed(
            $entry,
            $context,
        );
        $this->placement->assertAddPlacement(
            $entry,
            $entry->getDn()->normalize(),
            $context->isSystem(),
            $bulkLoad !== null && $bulkLoad->replaceExisting,
        );

        // A bulk load keeps the operational attributes its source supplied.
        if ($bulkLoad !== null) {
            $this->operationalAttrs->applyForBulkLoad(
                $entry,
                $bulkLoad->actorDn->toString(),
            );
        } else {
            $this->operationalAttrs->applyForAdd(
                $entry,
                $context,
            );
        }

        $this->applySystemChanges(
            $entry,
            $command->systemChanges,
        );
        $context->controlEvaluator()?->evaluateAddition($entry);

        return $entry;
    }
}
