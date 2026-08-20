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
 * A matching rule that can reduce a value to a form an external index compares byte-for-byte.
 *
 * Keys must match exactly when `equals()` does; a rule that cannot promise that stays off the indexed path.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface IndexableComparatorInterface
{
    /**
     * The index form of a whole value, or null when the rule cannot key it.
     */
    public function indexKey(string $value): ?string;

    /**
     * The index form of a substring fragment, which keeps its edge spaces, or null when the rule has no substring form.
     */
    public function indexFragment(string $fragment): ?string;
}
