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

namespace FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Builds journal records for committed writes and appends them to the change journal.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChangeRecorder implements ChangeRecorderInterface
{
    public function __construct(
        private ChangeJournalInterface $journal,
        private LoggerInterface $logger = new NullLogger(),
    ) {}

    public function records(): bool
    {
        return true;
    }

    public function recordAdd(
        Entry $entry,
        WriteContext $context,
    ): void {
        $this->record(
            ChangeType::Add,
            $entry,
            $context,
        );
    }

    public function recordModify(
        Entry $entry,
        WriteContext $context,
    ): void {
        $this->record(
            ChangeType::Modify,
            $entry,
            $context,
        );
    }

    public function recordModRdns(
        array $moved,
        WriteContext $context,
    ): void {
        $this->appendAll(array_map(
            fn(MovedEntry $move): ?PendingChange => $this->changeFor(
                ChangeType::ModRdn,
                $move->entry,
                $context,
                previousDn: $move->previousDn,
            ),
            $moved,
        ));
    }

    public function recordDeletes(
        array $entries,
        WriteContext $context,
    ): void {
        $this->appendAll(array_map(
            fn(Entry $entry): ?PendingChange => $this->changeFor(
                ChangeType::Delete,
                $entry,
                $context,
                preImage: $entry->makeCopy(),
            ),
            $entries,
        ));
    }

    private function record(
        ChangeType $type,
        Entry $entry,
        WriteContext $context,
    ): void {
        $change = $this->changeFor(
            $type,
            $entry,
            $context,
        );

        if ($change === null) {
            return;
        }

        $this->journal->append($change);
    }

    /**
     * @param list<?PendingChange> $changes those skipped are null
     */
    private function appendAll(array $changes): void
    {
        $this->journal->appendAll(array_values(array_filter($changes)));
    }

    /**
     * The record to journal, or null when the entry carries nothing to identify it by.
     */
    private function changeFor(
        ChangeType $type,
        Entry $entry,
        WriteContext $context,
        ?Dn $previousDn = null,
        ?Entry $preImage = null,
    ): ?PendingChange {
        $uuid = $entry->getUuid();

        // entryUUID is stamped on every write.
        // but account for bad data by skipping journal entries on potentially corrupt data (maybe a seed import).
        if ($uuid === null) {
            $this->logger->warning(
                'Skipping journal record for an entry missing a required attribute.',
                [
                    'changeType' => $type->value,
                    'dn' => $entry->getDn()->toString(),
                    'attribute' => AttributeTypeOid::NAME_ENTRY_UUID,
                ],
            );

            return null;
        }

        return new PendingChange(
            changeType: $type,
            dn: $entry->getDn(),
            entryUuid: $uuid,
            authzId: $context->getAuthzId(),
            previousDn: $previousDn,
            preImage: $preImage,
        );
    }
}
