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

use FreeDSx\Ldap\Search\Filter\FilterInterface;

/**
 * What a filter's items need for every entry it is evaluated against.
 *
 * Note: This is its own object so each evaluation shares it (where an array read out of a WeakMap would be a copy).
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class FilterPlan
{
    /**
     * Each equality item's canonical key by object id, true when its rule has no key, or false when it is Undefined.
     *
     * @var array<int, string|bool>
     */
    public array $equalities = [];

    /**
     * Whether each ordered or extensible match item's assertion is valid, by object id.
     *
     * @var array<int, bool>
     */
    public array $validItems = [];

    /**
     * The keys each OR's equality items merge into per attribute by the OR's object id, or false until it is grouped.
     *
     * @var array<int, array<string, array<int|string, true>>|false>
     */
    public array $keySets = [];

    /**
     * The children each grouped OR still evaluates one by one, by the OR's object id.
     *
     * @var array<int, list<FilterInterface>>
     */
    public array $ungrouped = [];
}
