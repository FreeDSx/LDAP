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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoEntryDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\AttributeIndexForms;

/**
 * Keeps an entry's secondary indexes, the attribute-value sidecar and any substring index, in step with its row.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryIndexWriter
{
    public function __construct(
        private PdoEntryDialectInterface $dialect,
        private PdoStatementPool $statements,
        private AttributeIndexForms $indexForms,
        private ?SubstringIndexInterface $substringIndex = null,
    ) {}

    /**
     * Replace every index row for the entry, for a new entry or an explicit rebuild.
     */
    public function rewrite(
        int $entryId,
        Entry $entry,
    ): void {
        $this->statements->execute(
            $this->dialect->querySidecarDelete(),
            [$entryId],
        );
        $this->insertRows($entryId, $entry);
        $this->maintainSubstringIndex($entryId, $entry);
    }

    /**
     * Touch only the index rows of attributes whose values differ from those of the currently stored entry.
     */
    public function update(
        int $entryId,
        Entry $entry,
        Entry $current,
    ): void {
        $changed = $this->changedNames($entry, $current);
        if ($changed === []) {
            return;
        }

        $this->statements->execute(
            $this->dialect->querySidecarDeleteNames(count($changed)),
            [$entryId, ...$changed],
        );
        $this->insertRows(
            $entryId,
            $entry,
            array_fill_keys($changed, true),
        );

        // A substring index keys off its own attribute set, so it only needs redoing when one of those changed.
        if (!$this->indexCovers($changed)) {
            return;
        }

        $this->maintainSubstringIndex($entryId, $entry);
    }

    /**
     * Lowercased names whose value set differs between the two entries, in either direction.
     *
     * @return list<string>
     */
    private function changedNames(
        Entry $entry,
        Entry $current,
    ): array {
        $next = $this->valuesByName($entry);
        $previous = $this->valuesByName($current);

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
            $name = strtolower($attribute->getName());
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
        if ($this->substringIndex === null) {
            return false;
        }

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
        $this->substringIndex?->maintain(
            $entryId,
            $entry,
            function (string $sql, array $params): void {
                $this->statements->execute(
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
        $rows = $this->buildRows($entryId, $entry, $only);
        if ($rows === []) {
            return;
        }

        $placeholders = SqlFilterUtility::markers(
            count($rows),
            '(?, ?, ?, ?)',
        );
        $params = [];
        foreach ($rows as $row) {
            $params[] = $row[0];
            $params[] = $row[1];
            $params[] = $row[2];
            $params[] = $row[3];
        }

        $this->statements->execute(
            $this->dialect->querySidecarInsertPrefix() . $placeholders,
            $params,
        );
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
            $attrNameLower = strtolower($attribute->getName());
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
        return $this->substringIndex?->readsOriginalValue($attribute) === true
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
