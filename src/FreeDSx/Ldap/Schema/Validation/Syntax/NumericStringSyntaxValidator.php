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
 * Validates the Numeric String syntax (RFC 4517 §3.3.23): one or more digits and spaces.
 *
 * e.g. "15 079 672 281"
 */
final class NumericStringSyntaxValidator implements SyntaxValidatorInterface
{
    private const PATTERN = '/^[0-9 ]+$/D';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
