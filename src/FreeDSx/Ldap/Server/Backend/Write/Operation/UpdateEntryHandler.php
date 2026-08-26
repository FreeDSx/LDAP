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
use FreeDSx\Ldap\Server\Backend\Storage\AtomicWriter;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
use FreeDSx\Ldap\Server\Backend\Write\Command\UpdateCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Modifies an entry.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class UpdateEntryHandler
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
        UpdateCommand $command,
        WriteContext $context,
    ): void {
        $this->writer->write(function () use ($command, $context): void {
            $this->applyUpdate(
                $command,
                $context,
            );
        });
    }
}
