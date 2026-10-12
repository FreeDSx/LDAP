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
use FreeDSx\Ldap\Schema\Validation\Syntax\IntegerSyntaxValidator;

/**
 * Bit-mask comparator for bitwise AND (bitAndMatch) and OR (bitOrMatch) matching rules.
 */
final readonly class BitMaskComparator implements MatchingRuleComparatorInterface
{
    public function __construct(
        private bool $requireAllBits,
        private IntegerSyntaxValidator $integers = new IntegerSyntaxValidator(),
    ) {}

    public function equals(
        string $a,
        string $b,
    ): bool {
        if (!$this->integers->isValid($a) || !$this->integers->isValid($b)) {
            return false;
        }

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
