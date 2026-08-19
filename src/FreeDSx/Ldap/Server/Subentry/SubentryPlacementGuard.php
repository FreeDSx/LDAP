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

namespace FreeDSx\Ldap\Server\Subentry;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;

/**
 * Keeps subentries directly below an administrative point. RFC 3672.
 *
 * Storage is passed per call rather than injected, so each check runs on the caller's transaction.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubentryPlacementGuard
{
    /**
     * @throws OperationException
     */
    public function assertPlacement(
        EntryStorageInterface $storage,
        Entry $entry,
        Dn $dn,
        WriteContext $context,
    ): void {
        // Server-initiated writes replay a placement the provider already accepted.
        if ($context->isSystem() || !SubentryDetector::isSubentry($entry)) {
            return;
        }

        $parent = $dn->getParent();

        if ($parent === null) {
            throw new OperationException(
                'A subentry cannot be a naming context.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        $parentEntry = $storage->find($parent);

        // A missing parent is reported by the parent-exists check, which resolves the matched DN.
        if ($parentEntry === null || $this->isAdministrativePoint($parentEntry)) {
            return;
        }

        throw new OperationException(
            'A subentry must be placed directly below an administrative point.',
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }

    /**
     * Subentries would go silently inert if their administrative point stopped being one.
     *
     * @throws OperationException
     */
    public function assertAdministrativeRoleRetained(
        EntryStorageInterface $storage,
        Entry $updated,
        Dn $dn,
        WriteContext $context,
    ): void {
        if ($context->isSystem() || $this->isAdministrativePoint($updated)) {
            return;
        }

        if (!$this->hasSubentryChildren($storage, $dn)) {
            return;
        }

        throw new OperationException(
            'The administrative role cannot be removed while the entry holds subentries.',
            ResultCode::UNWILLING_TO_PERFORM,
        );
    }

    private function isAdministrativePoint(Entry $entry): bool
    {
        return ($entry->get(AttributeTypeOid::NAME_ADMINISTRATIVE_ROLE)?->getValues() ?? []) !== [];
    }

    private function hasSubentryChildren(
        EntryStorageInterface $storage,
        Dn $dn,
    ): bool {
        $stream = $storage->list(StorageListOptions::firstChild(
            $dn,
            SubentryVisibility::Only,
        ));

        foreach ($stream->entries as $ignored) {
            return true;
        }

        return false;
    }
}
