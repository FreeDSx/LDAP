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

namespace FreeDSx\Ldap\Schema\Matching;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Schema\Matching\Comparator\CaseIgnoreComparator;
use FreeDSx\Ldap\Schema\Schema;

/**
 * Resolves the EQUALITY rule an attribute type has, so every path deciding value equality asks the same question.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EqualityComparatorResolver
{
    public function __construct(
        private Schema $schema,
        private MatchingRuleComparatorInterface $default = new CaseIgnoreComparator(),
    ) {}

    /**
     * Falls back to the default when the type is undefined or has no rule anything implements.
     */
    public function for(string $attributeName): MatchingRuleComparatorInterface
    {
        // Options are not part of the type, so they are dropped before asking the schema about it.
        $equalityOid = $this->schema->getEqualityRuleOid(Attribute::normalizeName($attributeName));
        $comparator = $equalityOid !== null
            ? $this->schema->getComparator($equalityOid)
            : null;

        // Implementations disagree on whether a missing rule is undefined, so the permissive reading is taken.
        return $comparator ?? $this->default;
    }
}
