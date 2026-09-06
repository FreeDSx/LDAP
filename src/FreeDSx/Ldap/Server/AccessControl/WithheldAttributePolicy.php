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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Server\Token\TokenInterface;

/**
 * Answers whether an attribute is withheld from an identity, for the filter and the result path alike.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WithheldAttributePolicy
{
    public function __construct(
        private AccessControlInterface $accessControl,
        private ?Schema $schema = null,
    ) {}

    /**
     * Whether the schema marks the attribute confidential, and the token holds no grant over it.
     */
    public function isWithheldFromResult(
        string $attribute,
        TokenInterface $token,
    ): bool {
        // Matched on the base type, so "userPassword;binary" cannot evade a rule naming userPassword.
        $name = Attribute::normalizeName($attribute);

        if ($this->schema?->getAttributeType($name)?->isConfidential() !== true) {
            return false;
        }

        return !$this->accessControl->hasConfidentialAccess(
            $token,
            $name,
        );
    }

    /**
     * Whether the attribute is withheld from a filter.
     */
    public function isWithheldFromFilter(
        string $attribute,
        TokenInterface $token,
    ): bool {
        if ($this->isWithheldFromResult($attribute, $token)) {
            return true;
        }

        return !$this->accessControl->mayFilterOnAttribute(
            $token,
            Attribute::normalizeName($attribute),
        );
    }
}
