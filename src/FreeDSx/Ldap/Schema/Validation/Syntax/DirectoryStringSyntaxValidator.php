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
 * Validates the Directory String syntax (RFC 4517 §3.3.6): one or more UTF-8 characters, so never empty.
 *
 * e.g. "Jane Doe"
 */
final class DirectoryStringSyntaxValidator implements SyntaxValidatorInterface
{
    public function isValid(string $value): bool
    {
        return $value !== ''
            && Text::isUtf8($value);
    }
}
