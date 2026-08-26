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
use FreeDSx\Ldap\Server\Backend\Storage\Capability\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Write\AtomicWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Write\Command\ComputeUpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Modifies an entry with changes derived from its current state, under a lock a concurrent writer cannot cross.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class ComputeUpdateHandler
{
    use AppliesEntryUpdate;

    public function __construct(
        private EntryStorageInterface $storage,
        private AtomicWriter $writer,
        private EntryLocator $locator,
        private EntryMutation $mutation,
        private EntryPlacementGuard $placement,
        private ?ChangeRecorder $changeRecorder = null,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        ComputeUpdateCommand $command,
        WriteContext $context,
    ): void {
        $this->writer->write(function () use ($command, $context): void {
            $dn = $command->dn->normalize();

            // Taken before the read, so what the changes are derived from cannot move under them.
            if ($this->storage instanceof RowLockableInterface) {
                $this->storage->lockForWrite($dn);
            }

            $entry = $this->storage->find($dn);
            if ($entry === null) {
                return;
            }

            $changes = ($command->compute)($entry);
            if ($changes === []) {
                return;
            }

            // Applied inline, since going back through the dispatcher would open a second transaction around this one.
            $this->applyUpdate(
                new UpdateCommand(
                    $command->dn,
                    $changes,
                ),
                $context,
            );
        });
    }
}
