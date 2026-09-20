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
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Removes one entry, which has to be a leaf.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DeleteEntryHandler
{
    use WritesLockedEntry;

    public function __construct(
        private WriteEntryInterface&TransactionalWriteInterface $storage,
        private EntryLocator $locator,
        private EntryPlacementGuard $placement,
        private ?ChangeRecorder $changeRecorder = null,
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        DeleteCommand $command,
        WriteContext $context,
    ): void {
        $dn = $command->dn->normalize();

        $this->writeLockedEntry(
            $dn,
            $context,
            function (Entry $entry) use ($command, $context, $dn): void {
                $this->placement->assertDeletePlacement($command->dn);

                $this->storage->remove($dn);
                $this->changeRecorder?->recordDelete(
                    $entry,
                    $context,
                );
            },
        );
    }
}
