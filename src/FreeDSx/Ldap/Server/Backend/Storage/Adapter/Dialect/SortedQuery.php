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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect;

/**
 * A base entry query rewritten with an ORDER BY, plus its parameters in bind order.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class SortedQuery
{
    /**
     * @param list<string|int> $params
     */
    public function __construct(
        public string $sql,
        public array $params = [],
    ) {}
}
