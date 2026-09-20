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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoSidecarDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\NoSubstringIndex;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;

/**
 * Keeps an entry's secondary indexes, the attribute-value sidecar and any substring index, in step with its row.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryIndexWriter
{
    /**
     * Rows per sidecar statement. Four placeholders each, inside the 999 bound SQLite builds before 3.32 compile in.
     */
    private const SIDECAR_ROWS_PER_STATEMENT = 200;

    public function __construct(
        private PdoSidecarDialectInterface $dialect,
        private PdoConnection $connection,
        private AttributeIndexForms $indexForms,
        private LinkedAttributes $linked,
        private SubstringIndexInterface $substringIndex = new NoSubstringIndex(),
    ) {}

    /**
     * Replace every index row for the entry, for a new entry or an explicit rebuild.
     */
    public function rewrite(
        int $entryId,
        Entry $entry,
    ): void {
        $this->connection->execute(
            $this->dialect->querySidecarDelete(),
            [$entryId],
        );
        $this->insertRows($entryId, $entry);
        $this->maintainSubstringIndex($entryId, $entry);
    }

    /**
     * Touch only the index rows whose values differ from those of the currently stored entry.
     */
    public function update(
        int $entryId,
        Entry $entry,
        Entry $current,
    ): void {
        $next = $this->valuesByName($entry);
        $previous = $this->valuesByName($current);
        $changed = $this->changedNames($next, $previous);

        if ($changed === []) {
            return;
        }
        $removed = [];
        $added = [];

        // Gathered across every changed attribute first: a statement per attribute takes index locks in an
        // order that differs between writers, which concurrent writers deadlock on.
        foreach ($changed as $name) {
            // Diffed on the stored row, not the raw value, so a difference the index key folds away cannot strand a row.
            $wanted = $this->rowsByKey($name, $next[$name] ?? []);
            $held = $this->rowsByKey($name, $previous[$name] ?? []);

            foreach (array_keys(array_diff_key($held, $wanted)) as $valueLower) {
                $removed[] = [$name, $valueLower];
            }

            foreach (array_diff_key($wanted, $held) as [$valueLower, $valueOriginal]) {
                $added[] = [
                    $entryId,
                    $name,
                    $valueLower,
                    $valueOriginal,
                ];
            }
        }

        $this->deleteValues($entryId, $removed);
        $this->insert($added);

        // A substring index keys off its own attribute set, so it only needs redoing when one of those changed.
        if (!$this->indexCovers($changed)) {
            return;
        }

        $this->maintainSubstringIndex($entryId, $entry);
    }

    /**
     * Removes the named rows in one statement per chunk, in the order every writer builds them.
     *
     * @param list<array{string, string}> $values [attr_name_lower, value_lower] pairs
     */
    private function deleteValues(
        int $entryId,
        array $values,
    ): void {
        foreach (array_chunk($values, self::SIDECAR_ROWS_PER_STATEMENT) as $chunk) {
            $params = [$entryId];

            foreach ($chunk as [$attrNameLower, $valueLower]) {
                $params[] = $attrNameLower;
                $params[] = $valueLower;
            }

            $this->connection->execute(
                $this->dialect->querySidecarDeleteValues(count($chunk)),
                $params,
            );
        }
    }

    /**
     * One attribute's values in their stored form, keyed by the index key the sidecar row carries.
     *
     * @param list<string> $values
     *
     * @return array<string, array{string, string}> value_lower => [value_lower, value_original]
     */
    private function rowsByKey(
        string $attrNameLower,
        array $values,
    ): array {
        $rows = [];

        foreach ($values as $value) {
            $key = $this->valueLower($attrNameLower, $value);
            $rows[$key] = [
                $key,
                $this->valueOriginal($attrNameLower, $value),
            ];
        }

        return $rows;
    }

    /**
     * Lowercased names whose value set differs between the two entries, in either direction.
     *
     * @param array<string, list<string>> $next
     * @param array<string, list<string>> $previous
     *
     * @return list<string>
     */
    private function changedNames(
        array $next,
        array $previous,
    ): array {
        $changed = [];
        foreach ($next as $name => $values) {
            if (($previous[$name] ?? null) !== $values) {
                $changed[] = $name;
            }
        }

        foreach ($previous as $name => $values) {
            if (!isset($next[$name])) {
                $changed[] = $name;
            }
        }

        // Sorted, so concurrent writers take the sidecar's index locks in one order.
        sort($changed);

        return $changed;
    }

    /**
     * Attribute values keyed by lowercased name and sorted, so ordering alone never reads as a change.
     *
     * Every option-bearing form merges into one key.
     *
     * @return array<string, list<string>>
     */
    private function valuesByName(Entry $entry): array
    {
        $byName = [];

        foreach ($entry->getAttributes() as $attribute) {
            // Linked values are answered from the table holding them.
            if ($this->linked->links($attribute)) {
                continue;
            }
            $name = Attribute::normalizeName($attribute->getName());
            $byName[$name] = [
                ...$byName[$name] ?? [],
                ...array_values($attribute->getValues()),
            ];
        }

        return array_map(
            static function (array $values): array {
                sort($values);

                return $values;
            },
            $byName,
        );
    }

    /**
     * @param list<string> $changed
     */
    private function indexCovers(array $changed): bool
    {
        foreach ($changed as $name) {
            if ($this->substringIndex->indexes($name)) {
                return true;
            }
        }

        return false;
    }

    private function maintainSubstringIndex(
        int $entryId,
        Entry $entry,
    ): void {
        $this->substringIndex->maintain(
            $entryId,
            $entry,
            function (string $sql, array $params): void {
                $this->connection->execute(
                    $sql,
                    $params,
                );
            },
        );
    }

    /**
     * @param array<string, true>|null $only Lowercased attribute names to write, or null for every attribute.
     */
    private function insertRows(
        int $entryId,
        Entry $entry,
        ?array $only = null,
    ): void {
        $this->insert($this->buildRows($entryId, $entry, $only));
    }

    /**
     * Chunked so the placeholder count stays inside the bound SQLite builds before 3.32 compile in.
     *
     * @param list<array{int, string, string, string}> $rows
     */
    private function insert(array $rows): void
    {
        foreach (array_chunk($rows, self::SIDECAR_ROWS_PER_STATEMENT) as $chunk) {
            $params = [];
            foreach ($chunk as $row) {
                $params[] = $row[0];
                $params[] = $row[1];
                $params[] = $row[2];
                $params[] = $row[3];
            }

            $this->connection->execute(
                $this->dialect->querySidecarInsert(count($chunk)),
                $params,
            );
        }
    }

    /**
     * @param array<string, true>|null $only
     *
     * @return list<array{int, string, string, string}> (owner_entry_id, attr_name_lower, value_lower, value_original)
     */
    private function buildRows(
        int $entryId,
        Entry $entry,
        ?array $only,
    ): array {
        $rows = [];

        foreach ($entry->getAttributes() as $attribute) {
            // Linked values are answered from the table holding them.
            if ($this->linked->links($attribute)) {
                continue;
            }
            $attrNameLower = Attribute::normalizeName($attribute->getName());

            if ($only !== null && !isset($only[$attrNameLower])) {
                continue;
            }

            foreach ($attribute->getValues() as $value) {
                $rows[] = [
                    $entryId,
                    $attrNameLower,
                    $this->valueLower($attrNameLower, $value),
                    $this->valueOriginal($attrNameLower, $value),
                ];
            }
        }

        return $rows;
    }

    /**
     * Kept only for an index that reads it back.
     */
    private function valueOriginal(
        string $attribute,
        string $value,
    ): string {
        return $this->substringIndex->readsOriginalValue($attribute)
            ? $value
            : '';
    }

    /**
     * A value its rule cannot key still gets a row, so presence, sorting and scope checks keep seeing it.
     */
    private function valueLower(
        string $attribute,
        string $value,
    ): string {
        $key = $this->indexForms->key($attribute, $value);

        return $key === null
            ? SqlFilterUtility::normalize($value)
            : SqlFilterUtility::truncate($key);
    }
}
