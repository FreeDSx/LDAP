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

/**
 * Bit-mask comparator for bitwise AND (bitAndMatch) and OR (bitOrMatch) matching rules.
 */
final readonly class BitMaskComparator implements MatchingRuleComparatorInterface
{
    public function __construct(private bool $requireAllBits) {}

    public function equals(
        string $a,
        string $b,
    ): bool {
        $mask = (int) $b;

        return $this->requireAllBits
            ? ((int) $a & $mask) === $mask
            : ((int) $a & $mask) !== 0;
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return (int) $a <=> (int) $b;
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }
}
