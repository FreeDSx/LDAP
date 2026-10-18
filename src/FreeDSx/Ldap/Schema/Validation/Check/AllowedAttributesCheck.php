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
use FreeDSx\Ldap\Schema\Definition\AttributeUsage;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function array_flip;
use function array_merge;
use function sprintf;
use function strcasecmp;
use function strtolower;

/**
 * RFC 4512 2.4: every user attribute an entry holds must be one its object classes permit.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class AllowedAttributesCheck implements SchemaCheckInterface
{
    private const EXTENSIBLE_OBJECT = 'extensibleObject';

    public function __construct(private Schema $schema) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        // RFC 4512 4.3 lets extensibleObject hold any user attribute, which waives only this rule.
        if ($this->isExtensible($write->entry)) {
            return [];
        }

        $allowed = array_flip(array_merge(
            $classes->must,
            $classes->may,
        ));

        foreach ($write->entry->getAttributes() as $attribute) {
            $attrType = $this->schema->getAttributeType($attribute->getName());

            if ($attrType === null || $attrType->usage !== AttributeUsage::UserApplications) {
                continue;
            }
            if (isset($allowed[strtolower($attrType->names[0] ?? $attribute->getName())])) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::AllowedAttributes,
                    ResultCode::OBJECT_CLASS_VIOLATION,
                    sprintf(
                        'Attribute "%s" is not permitted by any object class.',
                        $attribute->getName(),
                    ),
                ),
            ];
        }

        return [];
    }

    private function isExtensible(Entry $entry): bool
    {
        foreach ($entry->get('objectClass')?->getValues() ?? [] as $objectClass) {
            if (strcasecmp($objectClass, self::EXTENSIBLE_OBJECT) === 0) {
                return true;
            }
        }

        return false;
    }
}
