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
 * Validates the OID syntax (RFC 4517 §3.3.26): a numeric OID or a descriptor (keystring).
 *
 * e.g. "1.3.6.1.4.1.1466.115.121.1.15"
 */
final class OidSyntaxValidator implements SyntaxValidatorInterface
{
    /**
     * RFC 4512 1.4: an arc carries no leading zero, and a numericoid needs at least one dot.
     */
    private const NUMERICOID = '(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*))+';

    private const DESCR = '[A-Za-z][A-Za-z0-9-]*';

    private const PATTERN = '/^(' . self::NUMERICOID . '|' . self::DESCR . ')$/D';

    private const NUMERICOID_PATTERN = '/^' . self::NUMERICOID . '$/D';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }

    /**
     * Whether the value spells an object identifier explicitly, needing no descriptor lookup to name one.
     */
    public static function isNumericForm(string $value): bool
    {
        return preg_match(self::NUMERICOID_PATTERN, $value) === 1;
    }
}
