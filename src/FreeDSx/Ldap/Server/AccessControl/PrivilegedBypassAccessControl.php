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
use FreeDSx\Ldap\Server\Token\PrivilegedTokenInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Wraps an access-control policy so a privileged (manager) token bypasses every check.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PrivilegedBypassAccessControl implements AccessControlInterface, BackendAwareInterface
{
    public function __construct(private AccessControlInterface $inner) {}

    public function setBackend(ReadBackendInterface $backend): void
    {
        if ($this->inner instanceof BackendAwareInterface) {
            $this->inner->setBackend($backend);
        }
    }

    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void {
        if ($token instanceof PrivilegedTokenInterface) {
            return;
        }

        $this->inner->authorizeOperation(
            $operation,
            $token,
            $dn,
        );
    }

    public function authorizeRelocation(
        TokenInterface $token,
        Dn $container,
        RelocationAccess $direction,
    ): void {
        if ($token instanceof PrivilegedTokenInterface) {
            return;
        }

        $this->inner->authorizeRelocation(
            $token,
            $container,
            $direction,
        );
    }

    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
        AttributeAccess $access,
    ): void {
        if ($token instanceof PrivilegedTokenInterface) {
            return;
        }

        $this->inner->authorizeAttribute(
            $token,
            $dn,
            $attribute,
            $access,
        );
    }

    public function authorizeControl(
        TokenInterface $token,
        Dn $dn,
        string $controlOid,
    ): void {
        if ($token instanceof PrivilegedTokenInterface) {
            return;
        }

        $this->inner->authorizeControl(
            $token,
            $dn,
            $controlOid,
        );
    }

    public function authorizeExtendedOperation(
        TokenInterface $token,
        string $oid,
    ): void {
        if ($token instanceof PrivilegedTokenInterface) {
            return;
        }

        $this->inner->authorizeExtendedOperation(
            $token,
            $oid,
        );
    }

    public function mayUseControl(
        TokenInterface $token,
        string $controlOid,
    ): bool {
        return $token instanceof PrivilegedTokenInterface
            || $this->inner->mayUseControl(
                $token,
                $controlOid,
            );
    }

    public function hasConfidentialAccess(
        TokenInterface $token,
        string $attribute,
    ): bool {
        return $token instanceof PrivilegedTokenInterface
            || $this->inner->hasConfidentialAccess(
                $token,
                $attribute,
            );
    }

    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry {
        if ($token instanceof PrivilegedTokenInterface) {
            return $entry;
        }

        return $this->inner->filterEntry(
            $token,
            $entry,
        );
    }

    public function stripUnreadableAttributes(
        TokenInterface $token,
        Entry $entry,
    ): Entry {
        if ($token instanceof PrivilegedTokenInterface) {
            return $entry;
        }

        return $this->inner->stripUnreadableAttributes(
            $token,
            $entry,
        );
    }

    public function isEntryVisible(
        TokenInterface $token,
        Entry $entry,
    ): bool {
        if ($token instanceof PrivilegedTokenInterface) {
            return true;
        }

        return $this->inner->isEntryVisible(
            $token,
            $entry,
        );
    }
}
