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

namespace FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\ReadBackendInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Applies the RFC 4511 §4.1.9 "subject to access controls" rule to a candidate matchedDN.
 */
trait MatchedDnAccessFilterTrait
{
    /**
     * Returns $matchedDn when the token may see the ancestor entry.
     */
    private function filterMatchedDn(
        ?Dn $matchedDn,
        TokenInterface $token,
        ReadBackendInterface $backend,
        AccessControlInterface $accessControl,
    ): ?Dn {
        if ($matchedDn === null) {
            return null;
        }

        try {
            $entry = $backend->get($matchedDn);
        } catch (OperationException) {
            return new Dn('');
        }

        if ($entry === null) {
            return new Dn('');
        }

        return $accessControl->filterEntry($token, $entry) === null
            ? new Dn('')
            : $matchedDn;
    }
}
