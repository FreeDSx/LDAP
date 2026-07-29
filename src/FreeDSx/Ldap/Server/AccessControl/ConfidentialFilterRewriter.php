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

namespace FreeDSx\Ldap\Server\AccessControl;

use FreeDSx\Ldap\Search\Filter\AndFilter;
use FreeDSx\Ldap\Search\Filter\FilterAttributeInterface;
use FreeDSx\Ldap\Search\Filter\FilterAttributes;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filter\NotFilter;
use FreeDSx\Ldap\Search\Filter\OrFilter;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function count;

/**
 * Folds assertions on withheld confidential attributes out of a filter, so their values never select candidates.
 *
 * A withheld attribute is treated as absent, matching the per-entry redaction, which makes its assertion false
 * and collapses the surrounding tree by boolean algebra. Constants are the RFC 4526 absolute filters.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class ConfidentialFilterRewriter
{
    public function __construct(private ConfidentialAttributePolicy $policy) {}

    /**
     * The filter with withheld assertions folded away, or the original when none apply.
     */
    public function rewrite(
        FilterInterface $filter,
        TokenInterface $token,
    ): FilterInterface {
        return $this->hasWithheldAttribute($filter, $token)
            ? $this->fold($filter, $token)
            : $filter;
    }

    /**
     * Whether rewriting collapsed the filter to the RFC 4526 absolute false, which no entry satisfies.
     */
    public function isAbsoluteFalse(FilterInterface $filter): bool
    {
        return $filter instanceof OrFilter
            && $filter->get() === [];
    }

    /**
     * A null referenced set is indeterminate, so there is nothing to fold on.
     */
    private function hasWithheldAttribute(
        FilterInterface $filter,
        TokenInterface $token,
    ): bool {
        foreach (FilterAttributes::referenced($filter) ?? [] as $attribute) {
            if ($this->policy->isWithheld($attribute, $token)) {
                return true;
            }
        }

        return false;
    }

    private function fold(
        FilterInterface $filter,
        TokenInterface $token,
    ): FilterInterface {
        return match (true) {
            $filter instanceof AndFilter => $this->foldAnd($filter, $token),
            $filter instanceof OrFilter => $this->foldOr($filter, $token),
            $filter instanceof NotFilter => $this->foldNot($filter, $token),
            default => $this->foldLeaf($filter, $token),
        };
    }

    /**
     * A false child makes the whole conjunction false.
     */
    private function foldAnd(
        AndFilter $filter,
        TokenInterface $token,
    ): FilterInterface {
        $kept = [];

        foreach ($filter->get() as $child) {
            $folded = $this->fold($child, $token);

            if ($this->isAbsoluteFalse($folded)) {
                return self::never();
            }

            $kept[] = $folded;
        }

        return new AndFilter(...$kept);
    }

    /**
     * A false child can never satisfy a disjunction, so it drops out; losing every child leaves it false.
     */
    private function foldOr(
        OrFilter $filter,
        TokenInterface $token,
    ): FilterInterface {
        $kept = [];

        foreach ($filter->get() as $child) {
            $folded = $this->fold($child, $token);

            if (!$this->isAbsoluteFalse($folded)) {
                $kept[] = $folded;
            }
        }

        // A lone survivor is returned bare, so dropping a branch does not leave a redundant wrapper behind.
        return match (count($kept)) {
            0 => self::never(),
            1 => $kept[0],
            default => new OrFilter(...$kept),
        };
    }

    /**
     * Negating an assertion false for every entry matches all of them.
     */
    private function foldNot(
        NotFilter $filter,
        TokenInterface $token,
    ): FilterInterface {
        $folded = $this->fold($filter->get(), $token);

        return $this->isAbsoluteFalse($folded)
            ? new AndFilter()
            : new NotFilter($folded);
    }

    private function foldLeaf(
        FilterInterface $filter,
        TokenInterface $token,
    ): FilterInterface {
        $attribute = $filter instanceof FilterAttributeInterface
            ? $filter->getAttribute()
            : null;

        if ($attribute === null) {
            return $filter;
        }

        return $this->policy->isWithheld($attribute, $token)
            ? self::never()
            : $filter;
    }

    /**
     * The RFC 4526 absolute false filter, which no entry satisfies.
     */
    private static function never(): OrFilter
    {
        return new OrFilter();
    }
}
