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
 * Validates the Delivery Method syntax (RFC 4517 §3.3.5): dollar separated delivery method keywords.
 *
 * e.g. "telephone $ physical"
 */
final class DeliveryMethodSyntaxValidator implements SyntaxValidatorInterface
{
    /**
     * The §3.3.5 pdm keywords, which are the only values the syntax admits.
     */
    private const METHOD = '(?:any|mhs|physical|telex|teletex|g3fax|g4fax|ia5|videotex|telephone)';

    /**
     * WSP is zero or more spaces, so the separator need not carry any. RFC 5234 2.3 makes the keywords themselves case-insensitive.
     */
    private const PATTERN = '/^' . self::METHOD . '(?: *\$ *' . self::METHOD . ')*$/Di';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
