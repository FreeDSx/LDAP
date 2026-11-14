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
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Applies the RFC 4511 §4.1.9 "subject to access controls" rule to a candidate matchedDN.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class MatchedDnFilter
{
    public function __construct(
        private ReadBackendInterface $backend,
        private AccessControlInterface $accessControl,
    ) {}

    /**
     * The matched DN when the token may see that entry, an empty DN when it may not, or null when there is none.
     */
    public function filter(
        ?Dn $matchedDn,
        TokenInterface $token,
    ): ?Dn {
        if ($matchedDn === null) {
            return null;
        }

        try {
            $entry = $this->backend->get($matchedDn);
        } catch (OperationException) {
            return new Dn('');
        }

        if ($entry === null) {
            return new Dn('');
        }

        $visible = $this->accessControl->isEntryVisible(
            $token,
            $entry,
        );

        return $visible
            ? $matchedDn
            : new Dn('');
    }
}
