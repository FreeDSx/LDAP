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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Storage\OperationalAttributeGenerator;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationGate;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * The entry a command leaves behind: applied, held to the schema, then stamped.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class EntryMutation
{
    public function __construct(
        private WriteEntryOperationHandler $entryHandler,
        private SchemaViolationGate $schemaGate,
        private OperationalAttributeGenerator $operationalAttrs,
    ) {}

    /**
     * @throws OperationException
     */
    public function forUpdate(
        Entry $entry,
        UpdateCommand $command,
        WriteContext $context,
    ): Entry {
        $updated = $this->entryHandler->apply($entry, $command);
        $this->schemaGate->assertModifyAllowed(
            $command,
            $updated,
            $context,
        );
        $this->operationalAttrs->applyForModify(
            $updated,
            $context,
        );

        return $updated;
    }

    /**
     * @throws OperationException
     */
    public function forMove(
        Entry $entry,
        MoveCommand $command,
        WriteContext $context,
    ): Entry {
        $moved = $this->entryHandler->apply($entry, $command);
        $this->schemaGate->assertMoveAllowed(
            $command,
            $moved,
            $context,
        );
        $this->operationalAttrs->applyForModify(
            $moved,
            $context,
        );

        return $moved;
    }
}
