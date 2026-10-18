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

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Schema\Matching\EqualityComparatorResolver;
use FreeDSx\Ldap\Schema\Matching\EquivalentValues;
use FreeDSx\Ldap\Schema\Validation\ObjectClassChain;
use FreeDSx\Ldap\Schema\Validation\RuleViolation;
use FreeDSx\Ldap\Schema\Validation\SchemaRule;
use FreeDSx\Ldap\Schema\Validation\SchemaWrite;

use function sprintf;

/**
 * RFC 4511 4.1.7: no two of an attribute's values may be equivalent.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class EquivalentValuesCheck implements SchemaCheckInterface
{
    public function __construct(private EqualityComparatorResolver $equalityResolver) {}

    public function check(
        SchemaWrite $write,
        ObjectClassChain $classes,
    ): array {
        // A modify checks only what it touched, since the rest was already checked when it was written.
        $only = $write->operation === OperationType::Modify
            ? self::namesChangedBy($write->changes)
            : null;

        foreach ($write->entry->getAttributes() as $attribute) {
            if ($only !== null && !isset($only[Attribute::normalizeName($attribute->getDescription())])) {
                continue;
            }
            if ($write->hasLinkedCount($attribute) || !$this->hasEquivalentValues($attribute)) {
                continue;
            }

            return [
                new RuleViolation(
                    SchemaRule::EquivalentValues,
                    ResultCode::ATTRIBUTE_OR_VALUE_EXISTS,
                    sprintf(
                        'Attribute "%s" is supplied an equivalent value more than once.',
                        $attribute->getDescription(),
                    ),
                ),
            ];
        }

        return [];
    }

    /**
     * Grouped by the rule's index key, so equality is only asked of values that could answer it.
     */
    private function hasEquivalentValues(Attribute $attribute): bool
    {
        return EquivalentValues::firstDuplicate(
            $this->equalityResolver->for($attribute->getName()),
            $attribute->getValues(),
        ) !== null;
    }

    /**
     * The attribute types a change list touches, normalized the way every other type lookup normalizes.
     *
     * @param Change[] $changes
     * @return array<string, true>
     */
    private static function namesChangedBy(array $changes): array
    {
        $names = [];

        foreach ($changes as $change) {
            $names[Attribute::normalizeName($change->getAttribute()->getDescription())] = true;
        }

        return $names;
    }
}
