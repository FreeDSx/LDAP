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
 * Validates the Bit String syntax (RFC 4517 §3.3.2): binary digits quoted and suffixed with B.
 *
 * e.g. "'0101'B"
 */
final class BitStringSyntaxValidator implements SyntaxValidatorInterface
{
    private const PATTERN = "/^'[01]*'[Bb]$/D";

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
