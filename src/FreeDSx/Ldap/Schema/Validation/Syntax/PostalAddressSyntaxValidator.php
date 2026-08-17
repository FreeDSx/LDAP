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

use FreeDSx\Ldap\Schema\Text;

/**
 * Validates the Postal Address syntax (RFC 4517 §3.3.28): dollar separated lines, each at least one character.
 *
 * e.g. "1234 Main St.$Anytown, CA 12345$USA"
 */
final class PostalAddressSyntaxValidator implements SyntaxValidatorInterface
{
    /**
     * §3.3.28 line-char admits any character but the separator and the escape, which are spelled \24 and \5C.
     */
    private const LINE = '(?:[^$\\\\]|\\\\24|\\\\5C)*';

    /**
     * The grammar makes a line at least one character, but common implementations store an empty one.
     */
    private const PATTERN = '/^' . self::LINE . '(?:\$' . self::LINE . ')*$/Du';

    public function isValid(string $value): bool
    {
        return $value !== ''
            && Text::isUtf8($value)
            && preg_match(self::PATTERN, $value) === 1;
    }
}
