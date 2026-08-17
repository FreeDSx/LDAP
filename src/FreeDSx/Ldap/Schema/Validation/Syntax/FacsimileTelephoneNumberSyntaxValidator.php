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
 * Validates the Facsimile Telephone Number syntax (RFC 4517 §3.3.11): a number with optional fax parameters.
 *
 * e.g. "+1 555 555 1234$fineResolution"
 */
final class FacsimileTelephoneNumberSyntaxValidator implements SyntaxValidatorInterface
{
    /**
     * The §3.3.11 fax-parameter keywords, which are the only parameters the syntax admits.
     */
    private const PARAMETER = '(?:twoDimensional|fineResolution|unlimitedLength|b4Length|a3Width|b4Width|uncompressed)';

    /**
     * Case-insensitive because RFC 5234 2.3 makes the quoted ABNF keywords so; the number itself is unaffected.
     */
    private const PATTERN = '/^'
        . PrintableStringSyntaxValidator::CHARACTER . '+'
        . '(?:\$' . self::PARAMETER . ')*'
        . '$/Di';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
