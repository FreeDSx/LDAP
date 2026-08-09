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
 * Validates the UUID syntax (RFC 4530 §2.1), whose string form RFC 4122 §3 defines as 8-4-4-4-12 hex digits.
 *
 * e.g. "597ae2f6-16a6-1027-98f4-d28b5365dc14"
 */
final class UuidSyntaxValidator implements SyntaxValidatorInterface
{
    /**
     * Both cases are accepted, since RFC 4122 §3 is case insensitive on input.
     */
    private const PATTERN = '/^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$/D';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
