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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;

/**
 * A pluggable substring-search index for the PDO backend.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface SubstringIndexInterface
{
    /**
     * DDL that creates this strategy's schema, applied after the baseline when the strategy is attached.
     *
     * @return list<string>
     */
    public function schemaStatements(PdoDialectInterface $dialect): array;

    /**
     * Whether this strategy indexes the attribute, so a write can skip re-indexing when none of its own changed.
     */
    public function indexes(string $attributeLower): bool;

    /**
     * Whether this strategy reads the sidecar's value_original for the attribute.
     */
    public function readsOriginalValue(string $attributeLower): bool;

    /**
     * Re-index one entry, running each write through the executor inside the caller's transaction.
     *
     * @param callable(string $sql, list<string|int> $params): void $execute
     */
    public function maintain(
        int $entryId,
        Entry $entry,
        callable $execute,
    ): void;

    /**
     * A candidate-narrowing WHERE fragment for a substring filter on an indexed attribute; null to decline.
     *
     * @param list<string> $fragments
     */
    public function buildSubstringPredicate(
        string $attributeLower,
        array $fragments,
    ): ?SqlFilterResult;
}
