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

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Write\WritableBackendTrait;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use Generator;

/**
 * Applies LDAP semantics over a pluggable EntryStorageInterface; writes are routed through EntryStorageInterface::atomic().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WritableStorageBackend implements WritableLdapBackendInterface, ResettableInterface
{
    use WritableBackendTrait;

    public function __construct(
        private readonly EntryStorageInterface $storage,
        private readonly WriteEntryOperationHandler $entryHandler = new WriteEntryOperationHandler(),
    ) {
    }

    public function reset(): void
    {
        if ($this->storage instanceof ResettableInterface) {
            $this->storage->reset();
        }
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

    /**
     * @throws OperationException
     */
    public function search(
        SearchRequest $request,
        ControlBag $controls = new ControlBag(),
    ): EntryStream {
        $baseDn = $request->getBaseDn() ?? new Dn('');
        $normBase = $baseDn->normalize();

        if ($request->getScope() === SearchRequest::SCOPE_BASE_OBJECT) {
            $entry = $this->storage->find($normBase);

            if ($entry === null) {
                $this->throwNoSuchObject($baseDn);
            }

            return new EntryStream($this->yieldSingle($entry));
        }

        if (!$this->storage->exists($normBase)) {
            $this->throwNoSuchObject($baseDn);
        }

        $subtree = $request->getScope() === SearchRequest::SCOPE_WHOLE_SUBTREE;
        $options = new StorageListOptions(
            baseDn: $normBase,
            subtree: $subtree,
            filter: $request->getFilter(),
            timeLimit: $request->getTimeLimit(),
            sizeLimit: $request->getSizeLimit(),
        );

        try {
            $stream = $this->storage->list($options);
        } catch (InvalidAttributeException $e) {
            throw new OperationException(
                $e->getMessage(),
                ResultCode::PROTOCOL_ERROR,
                $e,
            );
        }

        return new EntryStream(
            $this->wrapWithTimeLimitHandling($stream->entries),
            $stream->isPreFiltered,
        );
    }

    /**
     * @return Generator<Entry>
     */
    private function yieldSingle(Entry $entry): Generator
    {
        yield $entry;
    }

    /**
     * Converts TimeLimitExceededException from the storage generator into an LDAP OperationException.
     *
     * @param Generator<Entry> $generator
     * @return Generator<Entry>
     * @throws OperationException
     */
    private function wrapWithTimeLimitHandling(Generator $generator): Generator
    {
        try {
            foreach ($generator as $entry) {
                yield $entry;
            }
        } catch (TimeLimitExceededException) {
            throw new OperationException(
                'Time limit exceeded.',
                ResultCode::TIME_LIMIT_EXCEEDED,
            );
        }
    }

    /**
     * @throws OperationException
     */
    public function add(AddCommand $command): void
    {
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command): void {
            $dn = $command->entry->getDn()->normalize();
            $this->assertParentExists($storage, $dn);

            if ($storage->exists($dn)) {
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
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command): void {
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
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command): void {
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
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command): void {
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

            if ($storage->exists($normNew)) {
                $this->throwEntryAlreadyExists($newEntry->getDn());
            }

            $storage->remove($normOld);
            $storage->store($newEntry);
        });
    }

    /**
     * Runs the operation under storage->atomic() and maps storage-layer exceptions to LDAP result codes.
     *
     * @param callable(EntryStorageInterface): void $operation
     * @throws OperationException
     */
    private function writeAtomic(callable $operation): void
    {
        try {
            $this->storage->atomic($operation);
        } catch (DnTooLongException $e) {
            throw new OperationException(
                $e->getMessage(),
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e,
            );
        }
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

        if (!$storage->exists($parent)) {
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

        if ($normNewParent->getParent() !== null && !$storage->exists($normNewParent)) {
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
