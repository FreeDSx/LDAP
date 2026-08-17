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
 * Validates the Teletex Terminal Identifier syntax (RFC 4517 §3.3.32): a terminal id with optional keyed parameters.
 *
 * e.g. "terminal-1$graphic:on"
 */
final class TeletexTerminalIdentifierSyntaxValidator implements SyntaxValidatorInterface
{
    /**
     * The §3.3.32 ttx-key keywords, which are the only parameter names the syntax admits.
     */
    private const KEY = '(?:graphic|control|misc|page|private)';

    /**
     * §3.3.32 ttx-value admits any octet but the separator and the escape, which are spelled \24 and \5C, and it
     * may be empty.
     */
    private const VALUE = '(?:[\x00-\x23\x25-\x5B\x5D-\xFF]|\\\\24|\\\\5C)*';

    /**
     * Case-insensitive because RFC 5234 2.3 makes the quoted ABNF keywords so; the value keeps its own octets.
     */
    private const PATTERN = '/^'
        . PrintableStringSyntaxValidator::CHARACTER . '+'
        . '(?:\$' . self::KEY . ':' . self::VALUE . ')*'
        . '$/Di';

    public function isValid(string $value): bool
    {
        return preg_match(self::PATTERN, $value) === 1;
    }
}
