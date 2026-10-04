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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationAccess;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Decides with whichever policy was installed last.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class ReloadableAccessControl implements AccessControlInterface, BackendAwareInterface
{
    private ?ReadBackendInterface $backend = null;

    public function __construct(private AccessControlInterface $current) {}

    /**
     * Every later decision uses the new policy, including those of an operation already in progress (RFC 4513 §6.1).
     */
    public function replace(AccessControlInterface $policy): void
    {
        if ($this->backend !== null && $policy instanceof BackendAwareInterface) {
            $policy->setBackend($this->backend);
        }

        $this->current = $policy;
    }

    public function setBackend(ReadBackendInterface $backend): void
    {
        $this->backend = $backend;

        if ($this->current instanceof BackendAwareInterface) {
            $this->current->setBackend($backend);
        }
    }

    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void {
        $this->current->authorizeOperation(
            $operation,
            $token,
            $dn,
        );
    }

    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
        AttributeAccess $access,
    ): void {
        $this->current->authorizeAttribute(
            $token,
            $dn,
            $attribute,
            $access,
        );
    }

    public function authorizeRelocation(
        TokenInterface $token,
        Dn $container,
        RelocationAccess $direction,
    ): void {
        $this->current->authorizeRelocation(
            $token,
            $container,
            $direction,
        );
    }

    public function authorizeControl(
        TokenInterface $token,
        Dn $dn,
        string $controlOid,
    ): void {
        $this->current->authorizeControl(
            $token,
            $dn,
            $controlOid,
        );
    }

    public function authorizeExtendedOperation(
        TokenInterface $token,
        string $oid,
    ): void {
        $this->current->authorizeExtendedOperation(
            $token,
            $oid,
        );
    }

    public function mayUseControl(
        TokenInterface $token,
        string $controlOid,
    ): bool {
        return $this->current->mayUseControl(
            $token,
            $controlOid,
        );
    }

    public function hasConfidentialAccess(
        TokenInterface $token,
        string $attribute,
    ): bool {
        return $this->current->hasConfidentialAccess(
            $token,
            $attribute,
        );
    }

    public function mayFilterOnAttribute(
        TokenInterface $token,
        string $attribute,
    ): bool {
        return $this->current->mayFilterOnAttribute(
            $token,
            $attribute,
        );
    }

    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry {
        return $this->current->filterEntry(
            $token,
            $entry,
        );
    }

    public function stripUnreadableAttributes(
        TokenInterface $token,
        Entry $entry,
    ): Entry {
        return $this->current->stripUnreadableAttributes(
            $token,
            $entry,
        );
    }

    public function isEntryVisible(
        TokenInterface $token,
        Entry $entry,
    ): bool {
        return $this->current->isEntryVisible(
            $token,
            $entry,
        );
    }
}
