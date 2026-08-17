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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\InvalidArgumentException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaRuleException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Operation\WriteEntryOperationHandler;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Write\Command\AddCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Search\Filter\EqualityFilter;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\InvalidAttributeException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Schema\SchemaValidationMode;
use FreeDSx\Ldap\Schema\Validation\SchemaValidator;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationDisposition;
use FreeDSx\Ldap\Server\Backend\Write\WritableLdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Filter\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Subentry\SubentryPlacementGuard;
use FreeDSx\Ldap\Server\Subentry\SubentryVisibility;
use Generator;

/**
 * Applies LDAP semantics over a pluggable EntryStorageInterface; writes are routed through EntryStorageInterface::atomic().
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class WritableStorageBackend implements WritableLdapBackendInterface, ResettableInterface
{
    /**
     * Entries removed per transaction during a subtree delete; bounds per-transaction work for large subtrees.
     */
    private const SUBTREE_DELETE_BATCH_SIZE = 1000;

    /**
     * @param ?ChangeRecorder $changeRecorder Present only when a journal is configured to append to.
     */
    public function __construct(
        private readonly EntryStorageInterface $storage,
        private readonly SearchStreamBuilder $searchStream,
        private readonly SchemaValidator $validator,
        private readonly StorageListOptionsFactory $listOptions,
        private readonly FilterEvaluatorInterface $filterEvaluator,
        private readonly OperationalAttributeGenerator $operationalAttrs = new OperationalAttributeGenerator(),
        private readonly WriteEntryOperationHandler $entryHandler = new WriteEntryOperationHandler(),
        private readonly ?ChangeRecorder $changeRecorder = null,
        private readonly SubentryPlacementGuard $subentryGuard = new SubentryPlacementGuard(),
    ) {}

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
            $this->throwNoSuchObject(
                $this->storage,
                $dn,
            );
        }

        // A comparison is an equality assertion, so it answers through the same evaluation a filter would get.
        return $this->filterEvaluator->evaluate(
            $entry,
            $filter,
        );
    }

    /**
     * @throws OperationException
     */
    public function search(
        SearchRequest $request,
        SubentryVisibility $subentries,
        ControlBag $controls = new ControlBag(),
        ?SearchLimits $effectiveLimits = null,
    ): EntryStream {
        $baseDn = $request->getBaseDn() ?? new Dn('');
        $normBase = $baseDn->normalize();

        if ($request->getScope() === SearchRequest::SCOPE_BASE_OBJECT) {
            return $this->searchBaseObject(
                $normBase,
                $baseDn,
                $request,
            );
        }

        $this->assertSearchBaseExists(
            $normBase,
            $baseDn,
            $request,
        );

        $options = $this->listOptions->make(
            $request,
            $normBase,
            $controls,
            $subentries,
            $effectiveLimits,
        );

        try {
            $stream = $this->storage->list($options);
        } catch (InvalidAttributeException) {
            # RFC 4511 §4.5.1.7: unrecognized attribute descriptions evaluate to Undefined; yield zero entries.
            return new EntryStream((static function (): Generator {
                yield from [];
            })());
        }

        return $this->searchStream->buildForList(
            $stream,
            $request,
            $effectiveLimits,
        );
    }

    public function supports(WriteRequestInterface $request): bool
    {
        return $request instanceof AddCommand
            || $request instanceof DeleteCommand
            || $request instanceof UpdateCommand
            || $request instanceof MoveCommand;
    }

    /**
     * @throws OperationException
     */
    public function handle(
        WriteRequestInterface $request,
        WriteContext $context,
    ): void {
        if ($request instanceof AddCommand) {
            $this->add(
                $request,
                $context,
            );
        } elseif ($request instanceof DeleteCommand) {
            $this->delete(
                $request,
                $context,
            );
        } elseif ($request instanceof UpdateCommand) {
            $this->update(
                $request,
                $context,
            );
        } elseif ($request instanceof MoveCommand) {
            $this->move(
                $request,
                $context,
            );
        }
    }

    /**
     * @throws OperationException
     */
    public function add(
        AddCommand $command,
        WriteContext $context,
    ): void {
        // Merged before validation, so the values naming the entry count toward what its object classes require.
        $command->entry->mergeRdnAttributes();

        // Validated up front: the entry is the caller's, and applying operational attributes below mutates it, so a
        // replayed transaction would otherwise re-validate an entry that now carries them.
        $this->validateForAdd(
            $command,
            $context,
        );

        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command, $context): void {
            $dn = $command->entry->getDn()->normalize();
            $this->assertParentExists(
                $storage,
                $dn,
                $context,
            );
            $this->subentryGuard->assertPlacement(
                $storage,
                $command->entry,
                $dn,
                $context,
            );

            if ($storage->exists($dn)) {
                $this->throwEntryAlreadyExists($command->entry->getDn());
            }

            $this->operationalAttrs->applyForAdd(
                $command->entry,
                $context,
            );
            $storage->store(
                $command->entry,
                rebuildIndexes: true,
            );
            $this->changeRecorder?->recordAdd(
                $storage,
                $command->entry,
                $context,
            );
        });
    }

    /**
     * @throws OperationException
     */
    public function delete(
        DeleteCommand $command,
        WriteContext $context,
    ): void {
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command, $context): void {
            $dn = $command->dn->normalize();
            $entry = $this->findOrFail(
                $storage,
                $dn,
            );

            if ($storage->hasChildren($dn)) {
                throw new OperationException(
                    sprintf(
                        'Entry "%s" has subordinate entries and cannot be deleted.',
                        $command->dn->toString(),
                    ),
                    ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                );
            }

            $this->assertNotNamingContext(
                $storage,
                $command->dn,
            );

            $storage->remove($dn);
            $this->changeRecorder?->recordDelete(
                $storage,
                $entry,
                $context,
            );
        });
    }

    /**
     * {@inheritDoc}
     *
     * @throws OperationException
     */
    public function deleteSubtree(
        DeleteCommand $command,
        WriteContext $context,
        callable $authorize,
    ): void {
        $base = $command->dn->normalize();
        $this->findOrFail(
            $this->storage,
            $base,
        );
        $this->assertNotNamingContext(
            $this->storage,
            $command->dn,
        );

        $dns = $this->collectSubtreeDnsDeepestFirst($base);

        // Authorize every entry up front so a denial aborts before any removal.
        foreach ($dns as $dn) {
            $authorize($dn);
        }

        foreach (array_chunk($dns, self::SUBTREE_DELETE_BATCH_SIZE) as $batch) {
            $this->writeAtomic(function (EntryStorageInterface $storage) use ($batch, $context): void {
                $preImages = $this->preImagesFor($storage, $batch);
                $storage->removeAll($batch);

                foreach ($preImages as $entry) {
                    $this->changeRecorder?->recordDelete(
                        $storage,
                        $entry,
                        $context,
                    );
                }
            });
        }
    }

    /**
     * @throws OperationException
     */
    public function update(
        UpdateCommand $command,
        WriteContext $context,
    ): void {
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command, $context): void {
            $this->applyUpdate(
                $storage,
                $command,
                $context,
            );
        });
    }

    /**
     * @inheritDoc
     *
     * @param callable(Entry): list<Change> $compute
     * @throws OperationException
     */
    public function atomicUpdate(
        Dn $dn,
        WriteContext $context,
        callable $compute,
    ): void {
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($dn, $context, $compute): void {
            $normalized = $dn->normalize();
            if ($storage instanceof RowLockableInterface) {
                $storage->lockForWrite($normalized);
            }

            $entry = $storage->find($normalized);
            if ($entry === null) {
                return;
            }

            $changes = $compute($entry);
            if ($changes === []) {
                return;
            }

            // Apply on the already-open storage rather than re-entering writeAtomic, which would re-enter the
            // serialized writer under Swoole and deadlock.
            $this->applyUpdate(
                $storage,
                new UpdateCommand(
                    $dn,
                    $changes,
                ),
                $context,
            );
        });
    }

    /**
     * @throws OperationException
     */
    public function move(
        MoveCommand $command,
        WriteContext $context,
    ): void {
        $this->writeAtomic(function (EntryStorageInterface $storage) use ($command, $context): void {
            $normOld = $command->dn->normalize();
            $entry = $this->findOrFail($storage, $normOld);

            if ($storage->hasChildren($normOld)) {
                throw new OperationException(
                    sprintf('Entry "%s" has subordinate entries and cannot be moved.', $command->dn->toString()),
                    ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                );
            }

            $this->assertNotNamingContext(
                $storage,
                $command->dn,
            );

            $this->assertNewSuperiorExists($storage, $command);

            $newEntry = $this->entryHandler->apply($entry, $command);
            $this->validateForMove(
                $command,
                $newEntry,
                $context,
            );
            $normNew = $newEntry->getDn()->normalize();

            if ($storage->exists($normNew)) {
                $this->throwEntryAlreadyExists($newEntry->getDn());
            }

            $this->subentryGuard->assertPlacement(
                $storage,
                $newEntry,
                $normNew,
                $context,
            );

            $this->operationalAttrs->applyForModify(
                $newEntry,
                $context,
            );
            $storage->remove($normOld);
            $storage->store(
                $newEntry,
                rebuildIndexes: true,
            );
            $this->changeRecorder?->recordModRdn(
                $storage,
                $newEntry,
                $command->dn,
                $context,
            );
        });
    }

    /**
     * A base scope search addresses one entry, so it bypasses the list options entirely.
     *
     * @throws OperationException
     */
    private function searchBaseObject(
        Dn $normBase,
        Dn $baseDn,
        SearchRequest $request,
    ): EntryStream {
        $entry = $this->storage->find($normBase);

        if ($entry === null) {
            $this->throwNoSuchObject(
                $this->storage,
                $baseDn,
            );
        }

        return $this->searchStream->buildForBaseObject(
            $entry,
            $request,
        );
    }

    /**
     * Entries the journal needs a pre-image of, read before they are removed; none when nothing is journaling.
     *
     * @param list<Dn> $batch
     *
     * @return list<Entry>
     */
    private function preImagesFor(
        EntryStorageInterface $storage,
        array $batch,
    ): array {
        if ($this->changeRecorder === null) {
            return [];
        }

        $entries = [];
        foreach ($batch as $dn) {
            $entry = $storage->find($dn);
            if ($entry !== null) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * Applies a modify within an already-open write; the caller owns the transaction.
     *
     * @throws OperationException
     */
    private function applyUpdate(
        EntryStorageInterface $storage,
        UpdateCommand $command,
        WriteContext $context,
    ): void {
        $dn = $command->dn->normalize();
        $entry = $this->findOrFail($storage, $dn);
        $updated = $this->entryHandler->apply($entry, $command);
        $this->validateForModify(
            $command,
            $updated,
            $context,
        );
        $this->subentryGuard->assertAdministrativeRoleRetained(
            $storage,
            $updated,
            $dn,
            $context,
        );
        $this->operationalAttrs->applyForModify(
            $updated,
            $context,
        );
        $storage->store($updated);
        $this->changeRecorder?->recordModify(
            $storage,
            $updated,
            $context,
        );
    }

    /**
     * Confirm the search base exists.
     *
     * When base-deref is requested, fetch it so an alias base can be declined.
     *
     * @throws OperationException
     */
    private function assertSearchBaseExists(
        Dn $normBase,
        Dn $baseDn,
        SearchRequest $request,
    ): void {
        // The RootDSE (empty base) is handled special elsewhere.
        if ($normBase->toString() === '') {
            return;
        }

        if (!$this->storage->exists($normBase)) {
            $this->throwNoSuchObject(
                $this->storage,
                $baseDn,
            );
        }
    }

    /**
     * @return Dn[] base entry and all descendants, deepest-first so children precede their parents.
     */
    private function collectSubtreeDnsDeepestFirst(Dn $base): array
    {
        $dns = [];
        $options = StorageListOptions::matchAll(
            $base,
            subtree: true,
            attributes: [],
        );

        foreach ($this->storage->list($options)->entries as $entry) {
            $dns[] = $entry->getDn()->normalize();
        }
        usort(
            $dns,
            static fn(Dn $a, Dn $b): int => $b->count() <=> $a->count(),
        );

        return $dns;
    }

    /**
     * @throws OperationException
     */
    private function validateForAdd(
        AddCommand $command,
        WriteContext $context,
    ): void {
        try {
            $this->validator->validateAdd(
                $command->entry,
                $context->isSystem(),
            );
        } catch (OperationException $e) {
            $this->recordOrReject(
                $e,
                $context,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function validateForModify(
        UpdateCommand $command,
        Entry $updated,
        WriteContext $context,
    ): void {
        try {
            $this->validator->validateModify(
                $command,
                $updated,
                $context->isSystem(),
            );
        } catch (OperationException $e) {
            $this->recordOrReject(
                $e,
                $context,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function validateForMove(
        MoveCommand $command,
        Entry $moved,
        WriteContext $context,
    ): void {
        try {
            $this->validator->validateModifyDn(
                $moved,
                $command->newRdn,
                $context->isSystem(),
            );
        } catch (OperationException $e) {
            $this->recordOrReject(
                $e,
                $context,
            );
        }
    }

    /**
     * Records the violation for audit and rejects it, unless policy or the Relax control allows the write.
     *
     * @throws OperationException
     */
    private function recordOrReject(
        OperationException $violation,
        WriteContext $context,
    ): void {
        $disposition = $this->dispositionFor(
            $violation,
            $context,
        );
        $context->schemaViolations()->record(
            $violation,
            $disposition,
        );

        if ($disposition === SchemaViolationDisposition::Rejected) {
            throw new SchemaRuleException(
                $violation,
                $context->schemaViolations(),
            );
        }
    }

    private function dispositionFor(
        OperationException $violation,
        WriteContext $context,
    ): SchemaViolationDisposition {
        if ($violation->getCode() === ResultCode::INVALID_ATTRIBUTE_SYNTAX) {
            return SchemaViolationDisposition::Rejected;
        }

        if ($context->getControls()->has(Control::OID_RELAX_RULES)) {
            return SchemaViolationDisposition::RelaxedByControl;
        }

        return $this->validator->mode() === SchemaValidationMode::Lenient
            ? SchemaViolationDisposition::RelaxedByPolicy
            : SchemaViolationDisposition::Rejected;
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
        } catch (StorageIoException $e) {
            throw new OperationException(
                'The backend storage is currently unavailable.',
                ResultCode::UNAVAILABLE,
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
            $this->throwNoSuchObject(
                $storage,
                $dn,
            );
        }

        return $entry;
    }

    /**
     * @throws OperationException
     */
    private function assertParentExists(
        EntryStorageInterface $storage,
        Dn $dn,
        WriteContext $context,
    ): void {
        $parent = $dn->getParent();

        if ($parent !== null && $storage->exists($parent)) {
            return;
        }

        // New naming-context roots may only be created by system writes.
        if ($context->isSystem()) {
            return;
        }

        $this->throwNoSuchObject(
            $storage,
            $parent ?? $dn,
        );
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
            $this->throwNoSuchObject(
                $storage,
                $command->newParent,
            );
        }
    }

    /**
     * @throws OperationException
     */
    private function assertNotNamingContext(
        EntryStorageInterface $storage,
        Dn $dn,
    ): void {
        $parent = $dn->normalize()->getParent();

        if ($parent !== null && $parent->toString() !== '' && $storage->exists($parent)) {
            return;
        }

        throw new OperationException(
            sprintf(
                'Entry "%s" is a naming context and cannot be deleted or renamed.',
                $dn->toString(),
            ),
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }

    /**
     * @throws OperationException
     */
    private function throwNoSuchObject(
        EntryStorageInterface $storage,
        Dn $dn,
    ): never {
        throw new OperationException(
            sprintf('No such object: %s', $dn->toString()),
            ResultCode::NO_SUCH_OBJECT,
            null,
            $this->findMatchedDn(
                $storage,
                $dn,
            ),
        );
    }

    /**
     * Walks up the parent chain to find the deepest ancestor that exists in the DIT (RFC 4511 §4.1.9).
     */
    private function findMatchedDn(
        EntryStorageInterface $storage,
        Dn $dn,
    ): ?Dn {
        try {
            $current = $dn->getParent();

            while ($current !== null) {
                if ($storage->exists($current->normalize())) {
                    return $current;
                }

                $current = $current->getParent();
            }
        } catch (InvalidArgumentException) {
            // DN has malformed components — no matched ancestor can be determined.
        }

        return null;
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
