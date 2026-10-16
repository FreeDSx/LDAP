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
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\TransactionalWriteInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Contract\WriteEntryInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\UnrecordedChanges;
use FreeDSx\Ldap\Server\Backend\Write\Command\DeleteSubtreeCommand;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

use function array_chunk;

/**
 * Removes an entry along with everything beneath it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DeleteSubtreeHandler
{
    /**
     * Entries removed per transaction; bounds per-transaction work for large subtrees.
     */
    private const BATCH_SIZE = 1000;

    public function __construct(
        private WriteEntryInterface $storage,
        private TransactionalWriteInterface $transaction,
        private EntryLocator $locator,
        private EntryPlacementGuard $placement,
        private SubtreeEnumerator $subtree,
        private ChangeRecorderInterface $changeRecorder = new UnrecordedChanges(),
    ) {}

    /**
     * @throws OperationException
     */
    public function handle(
        DeleteSubtreeCommand $command,
        WriteContext $context,
    ): void {
        $base = $command->dn->normalize();
        $this->locator->findOrFail($base);
        $this->placement->assertSubtreeDeletePlacement($command->dn);

        // Enumerated outside any transaction, since the removal below spans several of them.
        $dnList = $this->subtree->dnListDeepestFirst($base);

        foreach (array_chunk($dnList, self::BATCH_SIZE) as $batch) {
            $this->transaction->atomic(function () use ($batch, $context): void {
                $preImages = $this->changeRecorder->records()
                    ? $this->subtree->entriesAt($batch)
                    : [];
                $this->storage->removeAll($batch);

                foreach ($preImages as $entry) {
                    $this->changeRecorder->recordDelete(
                        $entry,
                        $context,
                    );
                }
            });
        }
    }
}
