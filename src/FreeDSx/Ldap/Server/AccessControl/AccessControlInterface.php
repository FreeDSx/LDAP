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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Server\AccessControl\Rule\AttributeAccess;
use FreeDSx\Ldap\Server\AccessControl\Rule\RelocationAccess;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Guards LDAP operations and read-side attribute visibility.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface AccessControlInterface
{
    /**
     * Assert that $token may perform $operation on $dn.
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeOperation(
        OperationType $operation,
        TokenInterface $token,
        Dn $dn,
    ): void;

    /**
     * Assert that $token may access $attribute on $dn for the given direction (Add and Modify are writes, Compare reads).
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeAttribute(
        TokenInterface $token,
        Dn $dn,
        string $attribute,
        AttributeAccess $access,
    ): void;

    /**
     * Assert that $token may move an entry out of, or into, the given container.
     *
     * Only consulted when a Modify DN changes the parent, so renaming an entry in place never reaches this.
     *
     * @param Dn $container The old parent for Out, the new parent for In.
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeRelocation(
        TokenInterface $token,
        Dn $container,
        RelocationAccess $direction,
    ): void;

    /**
     * Assert that the token may use the request control identified by the OID against the given DN.
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeControl(
        TokenInterface $token,
        Dn $dn,
        string $controlOid,
    ): void;

    /**
     * Assert that the token may invoke the privileged extended operation identified by the OID (deny-by-default).
     *
     * @throws OperationException with ResultCode::INSUFFICIENT_ACCESS_RIGHTS on denial
     */
    public function authorizeExtendedOperation(
        TokenInterface $token,
        string $oid,
    ): void;

    /**
     * Coarse, target-independent gate: whether $token could use the control against a target in general.
     *
     * Note: Only authenticated identities are considered.
     */
    public function mayUseControl(
        TokenInterface $token,
        string $controlOid,
    ): bool;

    /**
     * Whether $token holds a grant over an attribute the schema marks X-CONFIDENTIAL. Separate from attribute read
     * access, and required in addition to it.
     *
     * Target-independent by design: this is answered before a search runs, when no entry is in hand yet.
     */
    public function hasConfidentialAccess(
        TokenInterface $token,
        string $attribute,
    ): bool;

    /**
     * Whether $token may name an attribute in a search filter. Separate from read access, which only strips values.
     *
     * Target-independent by design: this is answered before a search runs, when no entry is in hand yet.
     */
    public function mayFilterOnAttribute(
        TokenInterface $token,
        string $attribute,
    ): bool;

    /**
     * Return $entry with unreadable attributes removed, or null to suppress the entry entirely.
     */
    public function filterEntry(
        TokenInterface $token,
        Entry $entry,
    ): ?Entry;

    /**
     * Return $entry with unreadable attributes removed, for callers that have already settled visibility.
     */
    public function stripUnreadableAttributes(
        TokenInterface $token,
        Entry $entry,
    ): Entry;

    /**
     * Whether $token may see $entry at all, without stripping any attributes (the entry-level gate replication uses).
     */
    public function isEntryVisible(
        TokenInterface $token,
        Entry $entry,
    ): bool;
}
