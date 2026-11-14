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

namespace FreeDSx\Ldap\Protocol\Queue\Budget;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Protocol\Authorization\AuthzId;
use FreeDSx\Ldap\Protocol\Authorization\AuthzIdType;
use FreeDSx\Ldap\Protocol\ServerAuthorization;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function intdiv;
use function max;
use function min;

/**
 * The share of its process's request budget held for the identity a connection is bound as.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class IdentityShare
{
    /**
     * One identity may hold this part of what its process may hold.
     */
    private const PARTS_OF_THE_LIMIT = 4;

    private ?TokenInterface $token = null;

    private ?BudgetShare $share = null;

    /**
     * @param int $limit the bytes one identity may hold.
     */
    public function __construct(
        private readonly ServerAuthorization $authorization,
        private readonly int $limit,
    ) {}

    /**
     * The bytes one identity may hold of the limit: a quarter, but never less than what the largest request holds.
     */
    public static function limitOf(
        int $limit,
        int $largestHeld,
    ): int {
        return min(
            $limit,
            max(
                intdiv(
                    $limit,
                    self::PARTS_OF_THE_LIMIT,
                ),
                $largestHeld,
            ),
        );
    }

    /**
     * The share of the identity the connection is bound as now, under one key however its DN is spelled.
     */
    public function current(): BudgetShare
    {
        $token = $this->authorization->getToken();

        if ($this->share !== null && $token === $this->token) {
            return $this->share;
        }
        $this->token = $token;

        return $this->share = new BudgetShare(
            self::keyOf($token->getAuthzId()),
            $this->limit,
        );
    }

    /**
     * Every anonymous and unauthenticated session shares the empty key.
     */
    private static function keyOf(AuthzId $authzId): string
    {
        if (!$authzId->isType(AuthzIdType::Dn)) {
            return $authzId->toString();
        }

        return AuthzIdType::Dn->value . Dn::normalized($authzId->getValue());
    }
}
