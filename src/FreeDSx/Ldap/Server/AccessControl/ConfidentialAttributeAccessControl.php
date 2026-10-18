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
use FreeDSx\Ldap\Server\AccessControl\Read\ConfidentialReadScope;
use FreeDSx\Ldap\Server\AccessControl\Read\ReadScopeInterface;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationAccess;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Wraps a policy so withheld confidential attributes are stripped from results whatever its own rules allow.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConfidentialAttributeAccessControl implements AccessControlInterface, BackendAwareInterface
{
    public function __construct(
        private AccessControlInterface $inner,
        private WithheldAttributePolicy $policy,
    ) {}

    public function setBackend(ReadBackendInterface $backend): void
    {
        if ($this->inner instanceof BackendAwareInterface) {
            $this->inner->setBackend($backend);
        }
    }

    public function readScope(TokenInterface $token): ReadScopeInterface
    {
        return new ConfidentialReadScope(
            $this->inner->readScope($token),
            $this->policy,
            $token,
        );
    }

    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void {
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
        string $oid,
    ): void {
        $this->inner->authorizeControl(
            $token,
            $dn,
            $oid,
        );
    }

    public function authorizeExtendedOperation(
        TokenInterface $token,
        string $oid,
    ): void {
        $this->inner->authorizeExtendedOperation(
            $token,
            $oid,
        );
    }

    public function mayUseControl(
        TokenInterface $token,
        string $controlOid,
    ): bool {
        return $this->inner->mayUseControl(
            $token,
            $controlOid,
        );
    }

    public function hasConfidentialAccess(
        TokenInterface $token,
        string $attribute,
    ): bool {
        return $this->inner->hasConfidentialAccess(
            $token,
            $attribute,
        );
    }

    public function mayFilterOnAttribute(
        TokenInterface $token,
        string $attribute,
    ): bool {
        return $this->inner->mayFilterOnAttribute(
            $token,
            $attribute,
        );
    }

    public function isEntryVisible(
        TokenInterface $token,
        Entry $entry,
    ): bool {
        return $this->inner->isEntryVisible($token, $entry);
    }
}
