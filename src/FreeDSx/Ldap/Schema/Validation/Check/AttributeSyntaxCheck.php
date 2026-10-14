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

namespace FreeDSx\Ldap\Schema\Validation\Check;

use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;
use FreeDSx\Ldap\Schema\Validation\Syntax\AttributeSyntaxResolver;

use function sprintf;

/**
 * Every value an entry holds must conform to its attribute type's syntax.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AttributeSyntaxCheck implements SchemaCheckInterface
{
    public function __construct(private AttributeSyntaxResolver $syntaxResolver) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        foreach ($write->entry->getAttributes() as $attribute) {
            if ($this->syntaxResolver->allConform($attribute)) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::AttributeSyntax,
                    ResultCode::INVALID_ATTRIBUTE_SYNTAX,
                    sprintf(
                        'A value for attribute "%s" does not conform to its syntax.',
                        $attribute->getName(),
                    ),
                ),
            ];
        }

        return [];
    }
}
