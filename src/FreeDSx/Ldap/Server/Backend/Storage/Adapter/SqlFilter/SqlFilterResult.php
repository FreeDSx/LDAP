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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter;

/**
 * An immutable value object holding a translated SQL filter fragment and its bound parameters.
 *
 * @see FilterTranslatorInterface
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class SqlFilterResult
{
    /**
     * Correlated `EXISTS` form referencing the outer `lc_dn` so an outer LIMIT can short-circuit, or null when none.
     */
    public readonly ?string $correlatedSql;

    /**
     * @param list<string> $params
     * @param ?string $sidecarCondition Single drivable leaf's sidecar WHERE body for the streaming fast path.
     * @param list<SidecarLeaf> $drivableLeaves A composed filter's drivable child leaves, for composed-filter streaming.
     * @param ?string $correlatedSql Explicit correlated form for composites; leaves derive it from $sidecarCondition.
     */
    public function __construct(
        public readonly string $sql,
        public readonly array $params,
        public readonly bool $isExact = true,
        public readonly ?string $sidecarCondition = null,
        public readonly array $drivableLeaves = [],
        ?string $correlatedSql = null,
    ) {
        $this->correlatedSql = $correlatedSql
            ?? ($sidecarCondition !== null ? self::correlatedLeaf($sidecarCondition) : null);
    }

    /**
     * Wraps a sidecar WHERE body as an `EXISTS` correlated to the outer entries row via the unqualified `lc_dn`.
     */
    public static function correlatedLeaf(string $sidecarCondition): string
    {
        return <<<SQL
            EXISTS (
                SELECT 1
                FROM entry_attribute_values s
                WHERE s.entry_lc_dn = lc_dn
                  AND $sidecarCondition)
            SQL;
    }
}
