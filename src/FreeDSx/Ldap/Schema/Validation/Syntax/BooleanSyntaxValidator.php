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
 * Validates the Boolean syntax (RFC 4517 §3.3.3): only the exact literals TRUE and FALSE.
 *
 * e.g. "TRUE"
 */
final class BooleanSyntaxValidator implements SyntaxValidatorInterface
{
    private const BOOLEAN_TRUE = 'TRUE';

    private const BOOLEAN_FALSE = 'FALSE';

    /**
     * RFC 5234 2.3 makes the quoted ABNF literals case-insensitive.
     */
    public function isValid(string $value): bool
    {
        $upper = strtoupper($value);

        return $upper === self::BOOLEAN_TRUE
            || $upper === self::BOOLEAN_FALSE;
    }
}
