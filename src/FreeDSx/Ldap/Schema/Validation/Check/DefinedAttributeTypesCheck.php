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
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function sprintf;

/**
 * An entry may only hold attribute types the schema defines.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DefinedAttributeTypesCheck implements SchemaCheckInterface
{
    public function __construct(private Schema $schema) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        foreach ($write->entry->getAttributes() as $attribute) {
            if ($this->schema->getAttributeType($attribute->getName()) !== null) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::DefinedAttributeTypes,
                    ResultCode::UNDEFINED_ATTRIBUTE_TYPE,
                    sprintf(
                        'Undefined attribute type: "%s".',
                        $attribute->getName(),
                    ),
                ),
            ];
        }

        return [];
    }
}
