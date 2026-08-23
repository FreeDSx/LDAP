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
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\ChangeType;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Change\PendingChange;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

/**
 * Builds journal records for committed writes and appends them to journaling-capable storage.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ChangeRecorder
{
    public function __construct(
        private EntryStorageInterface $storage,
        private LoggerInterface $logger = new NullLogger(),
    ) {}

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

    public function recordModRdn(
        Entry $entry,
        Dn $previousDn,
        WriteContext $context,
    ): void {
        $this->record(
            ChangeType::ModRdn,
            $entry,
            $context,
            previousDn: $previousDn,
        );
    }

    public function recordDelete(
        Entry $entry,
        WriteContext $context,
    ): void {
        $this->record(
            ChangeType::Delete,
            $entry,
            $context,
            preImage: $entry->makeCopy(),
        );
    }

    private function record(
        ChangeType $type,
        Entry $entry,
        WriteContext $context,
        ?Dn $previousDn = null,
        ?Entry $preImage = null,
    ): void {
        if (!$this->storage instanceof ChangeAppenderInterface) {
            return;
        }

        $uuid = $entry->get(AttributeTypeOid::NAME_ENTRY_UUID)?->firstValue();

        // entryUUID is stamped on every write.
        // but account for bad data by skipping journal entries on potentially corrupt data (maybe a seed import).
        if ($uuid === null || $uuid === '') {
            $this->logger->warning(
                'Skipping journal record for an entry missing a required attribute.',
                [
                    'changeType' => $type->value,
                    'dn' => $entry->getDn()->toString(),
                    'attribute' => AttributeTypeOid::NAME_ENTRY_UUID,
                ],
            );

            return;
        }

        $this->storage->appendChange(new PendingChange(
            changeType: $type,
            dn: $entry->getDn(),
            entryUuid: $uuid,
            authzId: $context->getAuthzId(),
            previousDn: $previousDn,
            preImage: $preImage,
        ));
    }
}
