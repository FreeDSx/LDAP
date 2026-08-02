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
 * Bit string comparator matching the bits within the 'nnnn'B form (RFC 4517 section 4.2.1).
 */
final class BitStringComparator implements MatchingRuleComparatorInterface
{
    public function equals(
        string $a,
        string $b,
    ): bool {
        return $this->bits($a) === $this->bits($b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcmp(
            $this->bits($a),
            $this->bits($b),
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return (new CaseExactComparator())->substringMatches(
            $this->bits($value),
            $assertion,
        );
    }

    /**
     * A value that is not in the 'nnnn'B form is compared as-is rather than silently reduced to nothing.
     */
    private function bits(string $value): string
    {
        $trimmed = trim($value);

        if (preg_match("/^'([01]*)'B$/", $trimmed, $matches) !== 1) {
            return $trimmed;
        }

        return $matches[1];
    }
}
