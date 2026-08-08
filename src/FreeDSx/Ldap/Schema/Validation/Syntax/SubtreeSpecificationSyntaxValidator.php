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

use FreeDSx\Ldap\Exception\SubtreeSpecificationParseException;
use FreeDSx\Ldap\Server\Subentry\SubtreeSpecificationParser;

/**
 * Validates the Subtree Specification syntax (RFC 3672 §2.1) by parsing the value.
 *
 * e.g. "{ base "ou=People", minimum 1 }"
 */
final class SubtreeSpecificationSyntaxValidator implements SyntaxValidatorInterface
{
    public function __construct(private readonly SubtreeSpecificationParser $parser = new SubtreeSpecificationParser()) {}

    public function isValid(string $value): bool
    {
        try {
            $this->parser->parse($value);

            return true;
        } catch (SubtreeSpecificationParseException) {
            return false;
        }
    }
}
