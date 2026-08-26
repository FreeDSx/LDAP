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

/**
 * Keeps subentries directly below an administrative point. RFC 3672.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SubentryPlacementGuard
{
    public function __construct(private EntryStorageInterface $storage) {}

    /**
     * @throws OperationException
     */
    public function assertPlacement(
        Entry $entry,
        Dn $dn,
        bool $isSystem,
    ): void {
        // Server-initiated writes replay a placement the provider already accepted.
        if ($isSystem || !SubentryDetector::isSubentry($entry)) {
            return;
        }

        $parent = $dn->getParent();

        if ($parent === null) {
            throw new OperationException(
                'A subentry cannot be a naming context.',
                ResultCode::UNWILLING_TO_PERFORM,
            );
        }

        $parentEntry = $this->storage->find($parent);

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
        Entry $updated,
        Dn $dn,
        bool $isSystem,
    ): void {
        if ($isSystem || $this->isAdministrativePoint($updated)) {
            return;
        }

        if (!$this->hasSubentryChildren($dn)) {
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

    private function hasSubentryChildren(Dn $dn): bool
    {
        $stream = $this->storage->list(StorageListOptions::firstChild(
            $dn,
            SubentryVisibility::Only,
        ));

        foreach ($stream->entries as $ignored) {
            return true;
        }

        return false;
    }
}
