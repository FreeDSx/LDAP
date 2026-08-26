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

use function count;

/**
 * Wraps a policy so withheld confidential attributes are stripped from results whatever its own rules allow.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConfidentialAttributeAccessControl implements AccessControlInterface, BackendAwareInterface
{
    public function __construct(
        private AccessControlInterface $inner,
        private ConfidentialAttributePolicy $policy,
    ) {}

    public function setBackend(ReadBackendInterface $backend): void
    {
        if ($this->inner instanceof BackendAwareInterface) {
            $this->inner->setBackend($backend);
        }
    }

    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry {
        $filtered = $this->inner->filterEntry($token, $entry);

        return $filtered === null
            ? null
            : $this->stripWithheld($filtered, $token);
    }

    public function stripUnreadableAttributes(
        TokenInterface $token,
        Entry $entry,
    ): Entry {
        return $this->stripWithheld(
            $this->inner->stripUnreadableAttributes($token, $entry),
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

    public function isEntryVisible(
        TokenInterface $token,
        Entry $entry,
    ): bool {
        return $this->inner->isEntryVisible($token, $entry);
    }

    /**
     * The entry itself is returned when nothing was withheld, so a caller can still tell it went untouched.
     */
    private function stripWithheld(
        Entry $entry,
        TokenInterface $token,
    ): Entry {
        $all = $entry->getAttributes();
        $kept = [];

        foreach ($all as $attribute) {
            if (!$this->policy->isWithheld($attribute->getName(), $token)) {
                $kept[] = $attribute;
            }
        }

        if (count($kept) === count($all)) {
            return $entry;
        }

        return Entry::raw(
            $entry->getDn(),
            $kept,
        );
    }
}
