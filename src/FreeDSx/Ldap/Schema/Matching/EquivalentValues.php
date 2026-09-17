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

/**
 * An attribute's values grouped by their rule's index key, so a candidate is only put to the values that could match.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class EquivalentValues
{
    /**
     * @var array<string, array<int, string>> Values by index key, each keyed by the position it arrived at.
     */
    private array $keyed = [];

    /**
     * @var array<int, string> Values the rule cannot key, keyed by the position each arrived at.
     */
    private array $unkeyed = [];

    private int $position = 0;

    private function __construct(
        private readonly MatchingRuleComparatorInterface $comparator,
        private readonly ?IndexableComparatorInterface $indexable,
    ) {}

    /**
     * @param iterable<string> $values
     */
    public static function of(
        MatchingRuleComparatorInterface $comparator,
        iterable $values,
    ): self {
        $held = new self(
            $comparator,
            $comparator instanceof IndexableComparatorInterface
                ? $comparator
                : null,
        );

        foreach ($values as $value) {
            $held->add($value);
        }

        return $held;
    }

    /**
     * The first value equivalent to one before it, or null when every value is distinct under the rule.
     *
     * @param iterable<string> $values
     */
    public static function firstDuplicate(
        MatchingRuleComparatorInterface $comparator,
        iterable $values,
    ): ?string {
        $held = self::of($comparator, []);

        foreach ($values as $value) {
            if ($held->containsEquivalentOf($value)) {
                return $value;
            }

            $held->add($value);
        }

        return null;
    }

    public function add(string $value): void
    {
        $key = $this->indexable?->indexKey($value);

        if ($key === null) {
            $this->unkeyed[$this->position++] = $value;

            return;
        }

        $this->keyed[$key][$this->position++] = $value;
    }

    public function containsEquivalentOf(string $candidate): bool
    {
        return $this->matching($candidate) !== [];
    }

    /**
     * The held values equal to the candidate, keyed by the position each arrived at.
     *
     * @return array<int, string>
     */
    public function matching(string $candidate): array
    {
        // Equal values share a key, so one the rule cannot key can only equal another it cannot key.
        $key = $this->indexable?->indexKey($candidate);
        $candidates = $key === null
            ? $this->unkeyed
            : $this->keyed[$key] ?? [];

        return array_filter(
            $candidates,
            fn(string $held): bool => $this->comparator->equals($held, $candidate),
        );
    }
}
