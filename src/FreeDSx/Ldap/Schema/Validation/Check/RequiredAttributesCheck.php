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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function sprintf;
use function strtolower;

/**
 * RFC 4512 2.4: an entry must hold every attribute its object classes require.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class RequiredAttributesCheck implements SchemaCheckInterface
{
    public function __construct(private Schema $schema) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        $present = $this->canonicalNamesOf($write->entry);

        foreach ($classes->must as $required) {
            if (isset($present[$required])) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::RequiredAttributes,
                    ResultCode::OBJECT_CLASS_VIOLATION,
                    sprintf(
                        'Required attribute "%s" is missing.',
                        $required,
                    ),
                ),
            ];
        }

        return [];
    }

    /**
     * @return array<string, true>
     */
    private function canonicalNamesOf(Entry $entry): array
    {
        $names = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attrType = $this->schema->getAttributeType($attribute->getName());
            $names[strtolower($attrType?->names[0] ?? $attribute->getName())] = true;
        }

        return $names;
    }
}
