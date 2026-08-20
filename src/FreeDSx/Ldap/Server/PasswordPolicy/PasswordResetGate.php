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

namespace FreeDSx\Ldap\Server\PasswordPolicy;

use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Schema\Definition\AttributeTypeOid;
use FreeDSx\Ldap\Server\Token\AuthenticatedTokenInterface;

/**
 * Decides which operations a pwdReset (must-change) identity may perform before changing its password.
 */
final class PasswordResetGate
{
    /**
     * StartTLS is named by §8.1.2.2, and RFC 3062 §4 wants password modify run under confidentiality.
     */
    private const PERMITTED_EXTENDED_OIDS = [
        ExtendedRequest::OID_PWD_MODIFY,
        ExtendedRequest::OID_START_TLS,
    ];

    /**
     * Whether the request is permitted while the bound identity must change its password (draft-behera-10 §8.1.2).
     */
    public function isPermitted(
        RequestInterface $request,
        AuthenticatedTokenInterface $token,
    ): bool {
        if ($request instanceof UnbindRequest || $request instanceof AbandonRequest) {
            return true;
        }
        if ($request instanceof ExtendedRequest) {
            return in_array(
                $request->getName(),
                self::PERMITTED_EXTENDED_OIDS,
                true,
            );
        }

        return $request instanceof ModifyRequest
            && $this->isSelfPasswordModify($request, $token);
    }

    /**
     * A modify of only the password attribute on the bound identity's own entry; nothing else may ride along.
     */
    private function isSelfPasswordModify(
        ModifyRequest $request,
        AuthenticatedTokenInterface $token,
    ): bool {
        $changes = $request->getChanges();
        if ($changes === []) {
            return false;
        }
        if ($request->getDn()->normalize()->toString() !== $token->getResolvedDn()->normalize()->toString()) {
            return false;
        }

        foreach ($changes as $change) {
            if (strcasecmp($change->getAttribute()->getName(), AttributeTypeOid::NAME_USER_PASSWORD) !== 0) {
                return false;
            }
        }

        return true;
    }
}
