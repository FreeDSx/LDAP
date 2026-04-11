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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use Generator;

/**
 * Orchestrates LDAP directory operations over a pluggable EntryStorageInterface.
 *
 * Handles all LDAP semantics — existence checks, subordinate checks, scope
 * filtering, DN normalisation, and entry transformation — so that storage
 * implementations only need to provide raw persistence primitives.
 *
 * All write operations are routed through EntryStorageInterface::atomic() to
 * ensure transactional consistency. See EntryStorageInterface::atomic() for the
 * contract each storage implementation must satisfy.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WritableStorageBackend implements WritableLdapBackendInterface
{
    use WritableBackendTrait;

    public function __construct(
        private readonly EntryStorageInterface $storage,
        private readonly WriteEntryOperationHandler $entryHandler = new WriteEntryOperationHandler(),
    ) {
    }

    public function get(Dn $dn): ?Entry
    {
        return $this->storage->find($dn->normalize());
    }

    /**
     * @throws OperationException
     */
    public function compare(
        Dn $dn,
        EqualityFilter $filter,
    ): bool {
        $entry = $this->get($dn);

        if ($entry === null) {
            $this->throwNoSuchObject($dn);
        }

        $attribute = $entry->get($filter->getAttribute());

        if ($attribute === null) {
            return false;
        }

        foreach ($attribute->getValues() as $value) {
            if (strcasecmp($value, $filter->getValue()) === 0) {
                return true;
            }
        }

        return false;
    }

    public function search(SearchContext $context): Generator
    {
        $normBase = $context->baseDn->normalize();

        if ($context->scope === SearchRequest::SCOPE_BASE_OBJECT) {
            $entry = $this->storage->find($normBase);
            if ($entry !== null) {
                yield $entry;
            }

            return;
        }

        foreach ($this->storage->list($normBase, $context->scope === SearchRequest::SCOPE_WHOLE_SUBTREE) as $entry) {
            yield $entry;
        }
    }

    /**
     * @throws OperationException
     */
    public function add(AddCommand $command): void
    {
        $this->storage->atomic(function (EntryStorageInterface $storage) use ($command): void {
            $dn = $command->entry->getDn()->normalize();
            $this->assertParentExists($storage, $dn);

            if ($storage->find($dn) !== null) {
                $this->throwEntryAlreadyExists($command->entry->getDn());
            }

            $storage->store($command->entry);
        });
    }

    /**
     * @throws OperationException
     */
    public function delete(DeleteCommand $command): void
    {
        $this->storage->atomic(function (EntryStorageInterface $storage) use ($command): void {
            $dn = $command->dn->normalize();
            $this->findOrFail($storage, $dn);

            if ($storage->hasChildren($dn)) {
                throw new OperationException(
                    sprintf(
                        'Entry "%s" has subordinate entries and cannot be deleted.',
                        $command->dn->toString()
                    ),
                    ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                );
            }

            $storage->remove($dn);
        });
    }

    /**
     * @throws OperationException
     */
    public function update(UpdateCommand $command): void
    {
        $this->storage->atomic(function (EntryStorageInterface $storage) use ($command): void {
            $dn = $command->dn->normalize();
            $entry = $this->findOrFail($storage, $dn);
            $storage->store($this->entryHandler->apply(
                $entry,
                $command,
            ));
        });
    }

    /**
     * @throws OperationException
     */
    public function move(MoveCommand $command): void
    {
        $this->storage->atomic(function (EntryStorageInterface $storage) use ($command): void {
            $normOld = $command->dn->normalize();
            $entry = $this->findOrFail($storage, $normOld);

            if ($storage->hasChildren($normOld)) {
                throw new OperationException(
                    sprintf('Entry "%s" has subordinate entries and cannot be moved.', $command->dn->toString()),
                    ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                );
            }

            $this->assertNewSuperiorExists($storage, $command);

            $newEntry = $this->entryHandler->apply($entry, $command);
            $normNew = $newEntry->getDn()->normalize();

            if ($storage->find($normNew) !== null) {
                $this->throwEntryAlreadyExists($newEntry->getDn());
            }

            $storage->remove($normOld);
            $storage->store($newEntry);
        });
    }

    /**
     * @throws OperationException
     */
    private function findOrFail(EntryStorageInterface $storage, Dn $dn): Entry
    {
        $entry = $storage->find($dn);

        if ($entry === null) {
            $this->throwNoSuchObject($dn);
        }

        return $entry;
    }

    /**
     * @throws OperationException
     */
    private function assertParentExists(EntryStorageInterface $storage, Dn $dn): void
    {
        $parent = $dn->getParent();

        // Skip check when the immediate parent is a root-level entry (single-component
        // DN), which is a valid naming context that may not be stored on this server.
        if ($parent === null || $parent->getParent() === null) {
            return;
        }

        if ($storage->find($parent) === null) {
            $this->throwNoSuchObject($parent);
        }
    }

    /**
     * @throws OperationException
     */
    private function assertNewSuperiorExists(EntryStorageInterface $storage, MoveCommand $command): void
    {
        if ($command->newParent === null) {
            return;
        }

        $normNewParent = $command->newParent->normalize();

        if ($normNewParent->getParent() !== null && $storage->find($normNewParent) === null) {
            $this->throwNoSuchObject($command->newParent);
        }
    }

    /**
     * @throws OperationException
     */
    private function throwNoSuchObject(Dn $dn): never
    {
        throw new OperationException(
            sprintf('No such object: %s', $dn->toString()),
            ResultCode::NO_SUCH_OBJECT,
        );
    }

    /**
     * @throws OperationException
     */
    private function throwEntryAlreadyExists(Dn $dn): never
    {
        throw new OperationException(
            sprintf('Entry already exists: %s', $dn->toString()),
            ResultCode::ENTRY_ALREADY_EXISTS,
        );
    }
}
