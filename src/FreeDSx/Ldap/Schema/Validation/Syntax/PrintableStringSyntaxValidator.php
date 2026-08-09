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
 * Validates the Printable String syntax (RFC 4517 §3.3.27): one or more printable characters.
 *
 * e.g. "Example Co., Ltd."
 */
final class PrintableStringSyntaxValidator implements SyntaxValidatorInterface
{
    private const PATTERN = '/^[A-Za-z0-9\'()+,\-.\/:? =]+$/D';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
