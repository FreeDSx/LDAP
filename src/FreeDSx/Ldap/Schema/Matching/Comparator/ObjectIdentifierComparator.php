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

namespace FreeDSx\Ldap\Schema\Matching\Comparator;

use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;
use FreeDSx\Ldap\Schema\Schema;

/**
 * RFC 4517 §4.2.26: values naming the same object identifier are equal however each one spells it.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ObjectIdentifierComparator implements MatchingRuleComparatorInterface
{
    public function __construct(
        private Schema $schema,
        private MatchingRuleComparatorInterface $unresolved = new CaseIgnoreComparator(),
    ) {}

    public function equals(
        string $a,
        string $b,
    ): bool {
        $oidA = $this->schema->oidFor($a);
        $oidB = $this->schema->oidFor($b);

        // A value naming nothing the schema defines has only its spelling to be compared on.
        if ($oidA === null || $oidB === null) {
            return $this->unresolved->equals($a, $b);
        }

        return $oidA === $oidB;
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return $this->unresolved->compare(
            $this->schema->oidFor($a) ?? $a,
            $this->schema->oidFor($b) ?? $b,
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return $this->unresolved->substringMatches($value, $assertion);
    }
}
