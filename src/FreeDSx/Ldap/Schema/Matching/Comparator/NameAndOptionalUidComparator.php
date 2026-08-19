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
use FreeDSx\Ldap\Schema\Matching\NameAndOptionalUid;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;

/**
 * RFC 4517 §4.2.34: the names have to match, and the identifier must be absent from both or equal in both.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class NameAndOptionalUidComparator implements MatchingRuleComparatorInterface
{
    public function __construct(
        private MatchingRuleComparatorInterface $name = new DistinguishedNameComparator(),
        private MatchingRuleComparatorInterface $uid = new BitStringComparator(),
    ) {}

    public function equals(
        string $a,
        string $b,
    ): bool {
        $left = NameAndOptionalUid::parse($a);
        $right = NameAndOptionalUid::parse($b);

        if (!$this->name->equals($left->name, $right->name)) {
            return false;
        }

        // One side carrying an identifier the other lacks is a mismatch, which is what makes the rule commutative.
        if ($left->uid === null || $right->uid === null) {
            return $left->uid === $right->uid;
        }

        return $this->uid->equals($left->uid, $right->uid);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        $left = NameAndOptionalUid::parse($a);
        $right = NameAndOptionalUid::parse($b);
        $byName = $this->name->compare($left->name, $right->name);

        if ($byName !== 0) {
            return $byName;
        }

        return $this->uid->compare(
            $left->uid ?? '',
            $right->uid ?? '',
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }
}
