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

namespace FreeDSx\Ldap\Server\Backend\Storage\Filter\Evaluation;

use FreeDSx\Ldap\Entry\Entry;

/**
 * One entry evaluated against one filter.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FilterEvaluation
{
    /**
     * The values each asserted description selects from the entry.
     *
     * @var array<string, array<string>>
     */
    public array $values = [];

    /**
     * The canonical keys of those values under each asserted description's equality rule.
     *
     * @var array<string, array<int|string, true>>
     */
    public array $keys = [];

    public function __construct(
        public readonly Entry $entry,
        public readonly FilterPlan $plan,
    ) {}
}
