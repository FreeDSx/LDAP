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

use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Server\Token\TokenInterface;

use function array_filter;
use function array_values;

/**
 * Drops sort keys naming an attribute withheld from the identity, so the result order cannot reflect its value.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class WithheldSortKeyFilter
{
    public function __construct(private WithheldAttributePolicy $policy) {}

    /**
     * Removes any key on a withheld attribute, leaving the control present so the sort is still reported as performed.
     */
    public function stripWithheld(
        SortingControl $control,
        TokenInterface $token,
    ): void {
        $kept = array_values(array_filter(
            $control->getSortKeys(),
            fn(SortKey $sortKey): bool => !$this->policy->isWithheldFromFilter(
                $sortKey->getAttribute(),
                $token,
            ),
        ));

        $control->setSortKeys(...$kept);
    }
}
