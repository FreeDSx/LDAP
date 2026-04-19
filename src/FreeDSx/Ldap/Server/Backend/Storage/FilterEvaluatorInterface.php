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

namespace FreeDSx\Ldap\Server\Backend\Storage;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * Evaluates an LDAP filter against an entry; implementations pick their own strategy (pure-PHP, SQL translation, etc).
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface FilterEvaluatorInterface
{
    /**
     * Returns true if the entry satisfies the filter, false otherwise.
     */
    public function evaluate(
        Entry $entry,
        FilterInterface $filter,
    ): bool;
}
