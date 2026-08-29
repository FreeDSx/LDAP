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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Subentry\SubentryPlacementGuard;

use function sprintf;

/**
 * Whether the DIT will have an entry where an operation is about to put one.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class EntryPlacementGuard
{
    public function __construct(
        private EntryStorageInterface $storage,
        private EntryLocator $locator,
        private SubentryPlacementGuard $subentries,
    ) {}

    /**
     * @throws OperationException
     */
    public function assertAddPlacement(
        Entry $entry,
        Dn $normDn,
        bool $isSystem,
    ): void {
        $this->assertParentExists(
            $normDn,
            $isSystem,
        );
        $this->subentries->assertPlacement(
            $entry,
            $normDn,
            $isSystem,
        );
        $this->assertDoesNotExist(
            $normDn,
            $entry->getDn(),
        );
    }

    /**
     * @throws OperationException
     */
    public function assertUpdatePlacement(
        Entry $updated,
        Dn $normDn,
        bool $isSystem,
    ): void {
        $this->subentries->assertAdministrativeRoleRetained(
            $updated,
            $normDn,
            $isSystem,
        );
    }

    /**
     * @throws OperationException
     */
    public function assertDeletePlacement(Dn $dn): void
    {
        $this->assertIsLeaf($dn);
        $this->assertNotNamingContext($dn);
    }

    /**
     * A subtree delete takes the subordinates with it, so it is held only to the naming context rule.
     *
     * @throws OperationException
     */
    public function assertSubtreeDeletePlacement(Dn $dn): void
    {
        $this->assertNotNamingContext($dn);
    }

    /**
     * @param Entry $moved The entry as the command leaves it, which is the only place the new DN exists.
     * @throws OperationException
     */
    public function assertMovePlacement(
        MoveCommand $command,
        Entry $moved,
        Dn $normOld,
        bool $isSystem,
    ): void {
        $this->assertNotNamingContext($command->dn);
        $this->assertNewSuperiorExists($command->newParent);
        $this->assertNotIntoOwnSubtree(
            $command->dn,
            $command->newParent,
        );

        $normNew = $moved->getDn()->normalize();
        // Respelling the RDN resolves to the entry being renamed, which is not a collision with another one.
        if ($normNew->toString() !== $normOld->toString()) {
            $this->assertTargetIsFree(
                $normNew,
                $moved->getDn(),
            );
        }

        $this->subentries->assertPlacement(
            $moved,
            $normNew,
            $isSystem,
        );
    }

    /**
     * @throws OperationException
     */
    private function assertParentExists(
        Dn $dn,
        bool $isSystem,
    ): void {
        $parent = $dn->getParent();

        if ($parent !== null && $this->storage->exists($parent)) {
            return;
        }
        // New naming-context roots may only be created by system writes.
        if ($isSystem) {
            return;
        }

        $this->locator->throwNoSuchObject($parent ?? $dn);
    }

    /**
     * A single-RDN superior is held to this too, so a move cannot strand the entry under a DN that holds nothing.
     *
     * Note: The RootDSE is never stored, and whether an entry may sit beneath it is settled before this runs.
     *
     * @throws OperationException
     */
    private function assertNewSuperiorExists(?Dn $newParent): void
    {
        if ($newParent === null || $newParent->isRootDse()) {
            return;
        }
        if (!$this->storage->exists($newParent->normalize())) {
            $this->locator->throwNoSuchObject($newParent);
        }
    }

    /**
     * @throws OperationException
     */
    private function assertIsLeaf(Dn $dn): void
    {
        if (!$this->storage->hasChildren($dn->normalize())) {
            return;
        }

        throw new OperationException(
            sprintf(
                'Entry "%s" has subordinate entries and cannot be deleted.',
                $dn->toString(),
            ),
            ResultCode::NOT_ALLOWED_ON_NON_LEAF,
        );
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
    private function assertDoesNotExist(
        Dn $normDn,
        Dn $dn,
    ): void {
        if (!$this->storage->exists($normDn)) {
            return;
        }

        $this->locator->throwEntryAlreadyExists($dn);
    }

    /**
     * The target must hold no entry, and nothing may already sit beneath it.
     *
     * @throws OperationException
     */
    private function assertTargetIsFree(
        Dn $normNew,
        Dn $newDn,
    ): void {
        // A system write may create an entry whose parent is absent, so the target can hold subordinates yet not exist.
        if (!$this->storage->exists($normNew) && !$this->storage->hasChildren($normNew)) {
            return;
        }

        $this->locator->throwEntryAlreadyExists($newDn);
    }

    /**
     * @throws OperationException
     */
    private function assertNotIntoOwnSubtree(
        Dn $dn,
        ?Dn $newParent,
    ): void {
        // Also what keeps the storage suffix rewrite well defined, so this is more than a sanity check.
        if ($newParent === null || !$newParent->normalize()->isDescendantOf($dn->normalize())) {
            return;
        }

        throw new OperationException(
            sprintf(
                'Entry "%s" cannot be moved beneath itself.',
                $dn->toString(),
            ),
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }
}
