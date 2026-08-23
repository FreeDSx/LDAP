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
        private readonly WriteEntryOperationHandler $entryHandler,
        private readonly SubentryPlacementGuard $subentryGuard,
        private readonly OperationalAttributeGenerator $operationalAttrs = new OperationalAttributeGenerator(),
        private readonly ?ChangeRecorder $changeRecorder = null,
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
            $this->throwNoSuchObject($dn);
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
        ?PageSlice $slice = null,
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
            $slice,
        );

        try {
            $stream = $this->storage->list($options);
        } catch (InvalidAttributeException) {
            # RFC 4511 §4.5.1.7: unrecognized attribute descriptions evaluate to Undefined; yield zero entries.
            return new EntryStream((static function (): Generator {
                yield from [];

                return null;
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

        $this->writeAtomic(function () use ($command, $context): void {
            $dn = $command->entry->getDn()->normalize();
            $this->assertParentExists(
                $dn,
                $context,
            );
            $this->subentryGuard->assertPlacement(
                $command->entry,
                $dn,
                $context,
            );

            if ($this->storage->exists($dn)) {
                $this->throwEntryAlreadyExists($command->entry->getDn());
            }

            $this->operationalAttrs->applyForAdd(
                $command->entry,
                $context,
            );
            $this->applySystemChanges(
                $command->entry,
                $command->systemChanges,
            );
            $this->storage->store(
                $command->entry,
                rebuildIndexes: true,
            );
            $this->changeRecorder?->recordAdd(
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
        $this->writeAtomic(function () use ($command, $context): void {
            $dn = $command->dn->normalize();
            $entry = $this->findOrFail($dn);

            if ($this->storage->hasChildren($dn)) {
                throw new OperationException(
                    sprintf(
                        'Entry "%s" has subordinate entries and cannot be deleted.',
                        $command->dn->toString(),
                    ),
                    ResultCode::NOT_ALLOWED_ON_NON_LEAF,
                );
            }

            $this->assertNotNamingContext($command->dn);

            $this->storage->remove($dn);
            $this->changeRecorder?->recordDelete(
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
        $this->findOrFail($base);
        $this->assertNotNamingContext($command->dn);

        $dns = $this->collectSubtreeDnsDeepestFirst($base);

        // Authorize every entry up front so a denial aborts before any removal.
        foreach ($dns as $dn) {
            $authorize($dn);
        }

        foreach (array_chunk($dns, self::SUBTREE_DELETE_BATCH_SIZE) as $batch) {
            $this->writeAtomic(function () use ($batch, $context): void {
                $preImages = $this->preImagesFor($batch);
                $this->storage->removeAll($batch);

                foreach ($preImages as $entry) {
                    $this->changeRecorder?->recordDelete(
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
        $this->writeAtomic(function () use ($command, $context): void {
            $this->applyUpdate(
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
        $this->writeAtomic(function () use ($dn, $context, $compute): void {
            $normalized = $dn->normalize();
            if ($this->storage instanceof RowLockableInterface) {
                $this->storage->lockForWrite($normalized);
            }

            $entry = $this->storage->find($normalized);
            if ($entry === null) {
                return;
            }

            $changes = $compute($entry);
            if ($changes === []) {
                return;
            }

            // Applied inline rather than through update(), which would open a second transaction around this one.
            $this->applyUpdate(
                new UpdateCommand(
                    $dn,
                    $changes,
                ),
                $context,
            );
        });
    }

    /**
     * Moves whatever is under the entry along with it.
     *
     * The containers an entry leaves and arrives in are gated by the relocation rules the middleware consults.
     *
     * @throws OperationException
     */
    public function move(
        MoveCommand $command,
        WriteContext $context,
    ): void {
        $normOld = $command->dn->normalize();
        $this->findOrFail($normOld);
        $this->assertNotNamingContext($command->dn);
        $this->assertNewSuperiorExists($command);
        $this->assertNotIntoOwnSubtree(
            $command,
            $normOld,
        );

        $this->writeAtomic(function () use ($command, $context, $normOld): void {
            $entry = $this->findOrFail($normOld);
            $newEntry = $this->entryHandler->apply($entry, $command);
            $this->validateForMove(
                $command,
                $newEntry,
                $context,
            );
            $normNew = $newEntry->getDn()->normalize();

            // Respelling the RDN resolves to the entry being renamed, which is not a collision with another one.
            $isRespelling = $normNew->toString() === $normOld->toString();

            if (!$isRespelling) {
                $this->assertMoveTargetIsFree(
                    $normNew,
                    $newEntry->getDn(),
                );
            }

            $this->subentryGuard->assertPlacement(
                $newEntry,
                $normNew,
                $context,
            );

            $this->operationalAttrs->applyForModify(
                $newEntry,
                $context,
            );

            // Re-keyed before the base is stored, so the upsert lands on the moved row rather than inserting a second.
            if (!$isRespelling) {
                $this->storage->renameSubtree(
                    $normOld,
                    $newEntry->getDn(),
                );
            }

            $this->storage->store($newEntry);
            $this->recordSubtreeMove(
                $context,
                $newEntry,
                $command->dn,
                $normOld,
                $normNew,
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
            $this->throwNoSuchObject($baseDn);
        }

        return $this->searchStream->buildForBaseObject(
            $entry,
            $request,
        );
    }

    /**
     * The target must hold no entry, and nothing may already sit beneath it.
     *
     * @throws OperationException
     */
    private function assertMoveTargetIsFree(
        Dn $normNew,
        Dn $newDn,
    ): void {
        // A system write may create an entry whose parent is absent, so the target can hold subordinates yet not exist.
        if (!$this->storage->exists($normNew) && !$this->storage->hasChildren($normNew)) {
            return;
        }

        $this->throwEntryAlreadyExists($newDn);
    }

    /**
     * @throws OperationException
     */
    private function assertNotIntoOwnSubtree(
        MoveCommand $command,
        Dn $normOld,
    ): void {
        // Also what keeps the storage suffix rewrite well defined, so this is more than a sanity check.
        if ($command->newParent === null || !$command->newParent->normalize()->isDescendantOf($normOld)) {
            return;
        }

        throw new OperationException(
            sprintf(
                'Entry "%s" cannot be moved beneath itself.',
                $command->dn->toString(),
            ),
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }

    /**
     * One record per moved entry, since a consumer re-fetches by the DN each record carries and would otherwise never
     * hear about a descendant.
     */
    private function recordSubtreeMove(
        WriteContext $context,
        Entry $newEntry,
        Dn $previousDn,
        Dn $normOld,
        Dn $normNew,
    ): void {
        if ($this->changeRecorder === null) {
            return;
        }

        $this->changeRecorder->recordModRdn(
            $newEntry,
            $previousDn,
            $context,
        );

        // Respelling the base leaves every DN beneath it exactly where it was.
        if ($normNew->toString() === $normOld->toString()) {
            return;
        }

        foreach ($this->movedDescendants($normNew) as $entry) {
            $this->changeRecorder->recordModRdn(
                $entry,
                $this->previousDnOf(
                    $entry->getDn(),
                    $normOld,
                    $normNew,
                ),
                $context,
            );
        }
    }

    /**
     * Read in full rather than streamed, so the journal writes below do not run against an open result set.
     *
     * @return list<Entry>
     */
    private function movedDescendants(Dn $normNew): array
    {
        $descendants = [];
        $options = StorageListOptions::matchAll(
            $normNew,
            subtree: true,
        );

        foreach ($this->storage->list($options)->entries as $entry) {
            if ($entry->getDn()->normalize()->toString() !== $normNew->toString()) {
                $descendants[] = $entry;
            }
        }

        return $descendants;
    }

    /**
     * Where a moved entry sat before, by swapping back the canonical suffix the move replaced.
     */
    private function previousDnOf(
        Dn $movedDn,
        Dn $normOld,
        Dn $normNew,
    ): Dn {
        $lcDn = $movedDn->normalize()->toString();

        return Dn::fromCanonical(
            substr(
                $lcDn,
                0,
                -strlen($normNew->toString()),
            ) . $normOld->toString(),
        );
    }

    /**
     * Entries the journal needs a pre-image of, read before they are removed; none when nothing is journaling.
     *
     * @param list<Dn> $batch
     *
     * @return list<Entry>
     */
    private function preImagesFor(array $batch): array
    {
        if ($this->changeRecorder === null) {
            return [];
        }

        $entries = [];
        foreach ($batch as $dn) {
            $entry = $this->storage->find($dn);
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
        UpdateCommand $command,
        WriteContext $context,
    ): void {
        $dn = $command->dn->normalize();
        $entry = $this->findOrFail($dn);
        $updated = $this->entryHandler->apply($entry, $command);
        $this->validateForModify(
            $command,
            $updated,
            $context,
        );
        $this->subentryGuard->assertAdministrativeRoleRetained(
            $updated,
            $dn,
            $context,
        );
        $this->operationalAttrs->applyForModify(
            $updated,
            $context,
        );
        $this->storage->store($updated);
        $this->changeRecorder?->recordModify(
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
            $this->throwNoSuchObject($baseDn);
        }
    }

    /**
     * @return Dn[] base entry and all descendants, deepest-first so children precede their parents.
     */
    private function collectSubtreeDnsDeepestFirst(Dn $base): array
    {
        $options = StorageListOptions::matchAll(
            $base,
            subtree: true,
            attributes: [],
        );

        $dns = [];
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

    /**
     * Applied alongside the operational attributes, so what the server stamps is never held to the user rules.
     *
     * @param list<Change> $changes
     */
    private function applySystemChanges(
        Entry $entry,
        array $changes,
    ): void {
        foreach ($changes as $change) {
            if ($change->getType() === Change::TYPE_REPLACE) {
                $entry->set($change->getAttribute());

                continue;
            }

            $entry->reset($change->getAttribute());
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
     * @param callable(): void $operation
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
    private function findOrFail(Dn $dn): Entry
    {
        $entry = $this->storage->find($dn);

        if ($entry === null) {
            $this->throwNoSuchObject($dn);
        }

        return $entry;
    }

    /**
     * @throws OperationException
     */
    private function assertParentExists(
        Dn $dn,
        WriteContext $context,
    ): void {
        $parent = $dn->getParent();

        if ($parent !== null && $this->storage->exists($parent)) {
            return;
        }

        // New naming-context roots may only be created by system writes.
        if ($context->isSystem()) {
            return;
        }

        $this->throwNoSuchObject($parent ?? $dn);
    }

    /**
     * A single-RDN superior is held to this too, so a move cannot strand the entry under a DN that holds nothing.
     *
     * @throws OperationException
     */
    private function assertNewSuperiorExists(MoveCommand $command): void
    {
        if ($command->newParent === null) {
            return;
        }

        if (!$this->storage->exists($command->newParent->normalize())) {
            $this->throwNoSuchObject($command->newParent);
        }
    }

    /**
     * @throws OperationException
     */
    private function assertNotNamingContext(Dn $dn): void
    {
        $parent = $dn->normalize()->getParent();

        if ($parent !== null && $parent->toString() !== '' && $this->storage->exists($parent)) {
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
    private function throwNoSuchObject(Dn $dn): never
    {
        throw new OperationException(
            sprintf('No such object: %s', $dn->toString()),
            ResultCode::NO_SUCH_OBJECT,
            null,
            $this->findMatchedDn($dn),
        );
    }

    /**
     * Walks up the parent chain to find the deepest ancestor that exists in the DIT (RFC 4511 §4.1.9).
     */
    private function findMatchedDn(Dn $dn): ?Dn
    {
        try {
            $current = $dn->getParent();

            while ($current !== null) {
                if ($this->storage->exists($current->normalize())) {
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
