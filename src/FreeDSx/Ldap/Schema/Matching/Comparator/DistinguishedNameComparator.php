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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Schema\Matching\IndexableComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\MatchingRuleComparatorInterface;
use FreeDSx\Ldap\Schema\Matching\SubstringAssertion;

/**
 * DN equality comparator (distinguishedNameMatch): normalizes both sides before comparing.
 */
final class DistinguishedNameComparator implements MatchingRuleComparatorInterface, IndexableComparatorInterface
{
    public function equals(
        string $a,
        string $b,
    ): bool {
        return $this->normalize($a) === $this->normalize($b);
    }

    public function compare(
        string $a,
        string $b,
    ): int {
        return strcmp(
            $this->normalize($a),
            $this->normalize($b),
        );
    }

    public function substringMatches(
        string $value,
        SubstringAssertion $assertion,
    ): bool {
        return false;
    }

    public function indexKey(string $value): string
    {
        return $this->normalize($value);
    }

    /**
     * The rule matches over parsed RDNs, so no fragment of a DN's spelling is meaningful to it.
     */
    public function indexFragment(string $fragment): ?string
    {
        return null;
    }

    private function normalize(string $dn): string
    {
        return (new Dn($dn))->normalize()->toString();
    }
}
