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

/**
 * Validates the Telex Number syntax (RFC 4517 §3.3.33): number, country code and answerback, dollar separated.
 *
 * e.g. "12345$US$ACME"
 */
final class TelexNumberSyntaxValidator implements SyntaxValidatorInterface
{
    /**
     * All three components are a PrintableString, so none of them may be empty.
     */
    private const PATTERN = '/^'
        . PrintableStringSyntaxValidator::CHARACTER . '+'
        . '\$' . PrintableStringSyntaxValidator::CHARACTER . '+'
        . '\$' . PrintableStringSyntaxValidator::CHARACTER . '+'
        . '$/D';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
