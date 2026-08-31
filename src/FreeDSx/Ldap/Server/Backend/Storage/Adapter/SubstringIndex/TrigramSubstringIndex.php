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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;

/**
 * Portable substring index: a generic trigram table usable across every PDO dialect.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class TrigramSubstringIndex implements SubstringIndexInterface
{
    /**
     * Attributes indexed by default: the common name/identity attributes typically searched by substring.
     *
     * @var list<string>
     */
    public const DEFAULT_ATTRIBUTES = [
        'cn',
        'sn',
        'givenName',
        'displayName',
        'uid',
        'mail',
        'ou',
    ];

    private const SCHEMA_NAME = 'trigram';

    private const DELETE_SQL = <<<SQL
        DELETE FROM entry_attribute_trigrams
        WHERE owner_entry_id = ?
        SQL;

    private const INSERT_SQL = <<<SQL
        INSERT INTO entry_attribute_trigrams (owner_entry_id, attr_name_lower, trigram)
        VALUES %s
        SQL;

    private const PREDICATE_SQL = <<<SQL
        entry_id IN (
            SELECT owner_entry_id FROM entry_attribute_trigrams
            WHERE attr_name_lower = ? AND trigram IN (%s)
            GROUP BY owner_entry_id
            HAVING COUNT(DISTINCT trigram) = %d
        )
        SQL;

    /**
     * @var array<string, true> Indexed attribute names, lowercased.
     */
    private readonly array $attributes;

    /**
     * @param list<string> $attributes
     */
    public function __construct(array $attributes = self::DEFAULT_ATTRIBUTES)
    {
        $set = [];

        foreach ($attributes as $attribute) {
            $set[strtolower($attribute)] = true;
        }

        $this->attributes = $set;
    }

    public function schemaStatements(PdoDialectInterface $dialect): array
    {
        return $dialect->schemaStatementsNamed(self::SCHEMA_NAME);
    }

    public function indexes(string $attributeLower): bool
    {
        return isset($this->attributes[$attributeLower]);
    }

    /**
     * Trigrams live in a table of their own, so the sidecar's copy of the value is never read.
     */
    public function readsOriginalValue(string $attributeLower): bool
    {
        return false;
    }

    public function maintain(
        int $entryId,
        Entry $entry,
        callable $execute,
    ): void {
        $execute(
            self::DELETE_SQL,
            [$entryId],
        );

        $rows = $this->rowsFor($entryId, $entry);
        if ($rows === []) {
            return;
        }

        $execute(
            sprintf(
                self::INSERT_SQL,
                $this->placeholders(count($rows)),
            ),
            $this->flatten($rows),
        );
    }

    public function buildSubstringPredicate(
        string $attributeLower,
        array $fragments,
    ): ?SqlFilterResult {
        if (!isset($this->attributes[$attributeLower])) {
            return null;
        }

        $trigrams = [];
        foreach ($fragments as $fragment) {
            foreach (Trigrams::of($fragment) as $trigram) {
                $trigrams[] = $trigram;
            }
        }
        $trigrams = array_values(array_unique($trigrams));

        if ($trigrams === []) {
            return null;
        }

        $markers = SqlFilterUtility::markers(count($trigrams));

        return new SqlFilterResult(
            sprintf(
                self::PREDICATE_SQL,
                $markers,
                count($trigrams),
            ),
            [$attributeLower, ...$trigrams],
            isExact: false,
        );
    }

    /**
     * @return list<array{0: int, 1: string, 2: string}>
     */
    private function rowsFor(
        int $entryId,
        Entry $entry,
    ): array {
        $rows = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attrLower = strtolower($attribute->getName());
            if (!isset($this->attributes[$attrLower])) {
                continue;
            }

            $trigrams = [];
            foreach ($attribute->getValues() as $value) {
                foreach (Trigrams::of($value) as $trigram) {
                    $trigrams[] = $trigram;
                }
            }

            foreach (array_unique($trigrams) as $trigram) {
                $rows[] = [$entryId, $attrLower, $trigram];
            }
        }

        return $rows;
    }

    private function placeholders(int $count): string
    {
        return SqlFilterUtility::markers(
            $count,
            '(?, ?, ?)',
        );
    }

    /**
     * @param list<array{0: int, 1: string, 2: string}> $rows
     *
     * @return list<string|int>
     */
    private function flatten(array $rows): array
    {
        $params = [];

        foreach ($rows as $row) {
            $params[] = $row[0];
            $params[] = $row[1];
            $params[] = $row[2];
        }

        return $params;
    }
}
