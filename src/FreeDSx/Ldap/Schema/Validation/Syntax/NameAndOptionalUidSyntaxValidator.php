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

namespace FreeDSx\Ldap\Schema\Validation\Syntax;

use FreeDSx\Ldap\Schema\Matching\NameAndOptionalUid;

/**
 * Validates the Name and Optional UID syntax (RFC 4517 §3.3.21): a DN with an optional bit string after it.
 *
 * e.g. "cn=Alice,dc=example,dc=com#'0101'B"
 */
final class NameAndOptionalUidSyntaxValidator implements SyntaxValidatorInterface
{
    private readonly DistinguishedNameSyntaxValidator $name;

    private readonly BitStringSyntaxValidator $uid;

    public function __construct()
    {
        $this->name = new DistinguishedNameSyntaxValidator();
        $this->uid = new BitStringSyntaxValidator();
    }

    public function isValid(string $value): bool
    {
        $parsed = NameAndOptionalUid::parse($value);

        if ($parsed->uid !== null && !$this->uid->isValid($parsed->uid)) {
            return false;
        }

        return $this->name->isValid($parsed->name);
    }
}
