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

use FreeDSx\Ldap\Schema\Definition\SyntaxOid;

/**
 * Maps a syntax OID to the validator that enforces it, if any.
 */
final class SyntaxValidatorRegistry
{
    /**
     * @param array<string, SyntaxValidatorInterface> $validators keyed by syntax OID
     */
    public function __construct(private readonly array $validators) {}

    /**
     * Builds a registry covering the syntaxes with crisp RFC 4517 rules.
     */
    public static function default(): self
    {
        return new self([
            SyntaxOid::OID_INTEGER => new IntegerSyntaxValidator(),
            SyntaxOid::OID_BOOLEAN => new BooleanSyntaxValidator(),
            SyntaxOid::OID_GENERALIZED_TIME => new GeneralizedTimeSyntaxValidator(),
            SyntaxOid::OID_DISTINGUISHED_NAME => new DistinguishedNameSyntaxValidator(),
            SyntaxOid::OID_OID => new OidSyntaxValidator(),
            SyntaxOid::OID_NUMERIC_STRING => new NumericStringSyntaxValidator(),
            SyntaxOid::OID_PRINTABLE_STRING => new PrintableStringSyntaxValidator(),
            SyntaxOid::OID_IA5_STRING => new Ia5StringSyntaxValidator(),
            SyntaxOid::OID_BIT_STRING => new BitStringSyntaxValidator(),
            SyntaxOid::OID_SUBTREE_SPECIFICATION => new SubtreeSpecificationSyntaxValidator(),
        ]);
    }

    /**
     * Returns the validator for a syntax OID, or null when the syntax is unconstrained.
     */
    public function get(string $syntaxOid): ?SyntaxValidatorInterface
    {
        return $this->validators[$syntaxOid] ?? null;
    }
}
