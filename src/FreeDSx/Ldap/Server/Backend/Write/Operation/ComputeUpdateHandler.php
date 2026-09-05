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
    use WritesLockedEntry;

    public function __construct(
        private EntryStorageInterface $storage,
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
        $dn = $command->dn->normalize();

        $this->writeLocked(
            $dn,
            function () use ($command, $context, $dn): void {
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
            },
        );
    }
}
