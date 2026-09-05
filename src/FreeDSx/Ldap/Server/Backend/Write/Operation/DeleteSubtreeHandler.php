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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\EntryLocator;
use FreeDSx\Ldap\Server\Backend\Storage\Directory\SubtreeEnumerator;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeRecorder;
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
        private EntryStorageInterface $storage,
        private EntryLocator $locator,
        private EntryPlacementGuard $placement,
        private SubtreeEnumerator $subtree,
        private AccessControlInterface $accessControl,
        private ?ChangeRecorder $changeRecorder = null,
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

        // Authorize every entry up front so a denial aborts before any removal.
        foreach ($dnList as $dn) {
            $this->authorize($dn, $context);
        }

        foreach (array_chunk($dnList, self::BATCH_SIZE) as $batch) {
            $this->storage->atomic(function () use ($batch, $context): void {
                $preImages = $this->changeRecorder === null
                    ? []
                    : $this->subtree->entriesAt($batch);
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
     * The client never named these entries, and the rules governing them are DN driven.
     *
     * @throws OperationException
     */
    private function authorize(
        Dn $dn,
        WriteContext $context,
    ): void {
        // Replay is privileged by construction, having already been authorized where the change originated.
        if ($context->isSystem()) {
            return;
        }

        $this->accessControl->authorizeOperation(
            OperationType::Delete,
            $context->getToken(),
            $dn,
        );
    }
}
