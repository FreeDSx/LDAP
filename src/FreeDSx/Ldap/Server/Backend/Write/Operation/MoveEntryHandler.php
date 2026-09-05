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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\SubtreeMoveRecorder;
use FreeDSx\Ldap\Server\Backend\Write\Command\MoveCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Renames an entry, carrying whatever sits beneath it along with it.
 *
 * The containers an entry leaves and arrives in are gated by the relocation rules the middleware consults.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MoveEntryHandler
{
    use WritesLockedEntry;

    public function __construct(
        private EntryStorageInterface $storage,
        private EntryLocator $locator,
        private EntryMutation $mutation,
        private EntryPlacementGuard $placement,
        private ?SubtreeMoveRecorder $moveRecorder = null,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        MoveCommand $command,
        WriteContext $context,
    ): void {
        $normOld = $command->dn->normalize();

        // Only the moved entry is locked; the destination is held by the unique key the rename and store land on.
        $this->writeLocked(
            $normOld,
            function () use ($command, $context, $normOld): void {
                $newEntry = $this->mutation->forMove(
                    $this->locator->findOrFail($normOld),
                    $command,
                    $context,
                );
                $this->placement->assertMovePlacement(
                    $command,
                    $newEntry,
                    $normOld,
                    $context->isSystem(),
                );

                $normNew = $newEntry->getDn()->normalize();
                // Re-keyed before the base is stored, so the upsert lands on the moved row rather than inserting a second.
                if ($normNew->toString() !== $normOld->toString()) {
                    $this->storage->renameSubtree(
                        $normOld,
                        $newEntry->getDn(),
                    );
                }

                $this->storage->store($newEntry);
                $this->moveRecorder?->record(
                    $context,
                    $newEntry,
                    $command->dn,
                    $normOld,
                    $normNew,
                );
            },
        );
    }
}
