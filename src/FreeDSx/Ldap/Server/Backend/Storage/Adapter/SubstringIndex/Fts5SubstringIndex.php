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
use FreeDSx\Ldap\Schema\Text;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use PDO;
use Throwable;

/**
 * Native SQLite substring index using an FTS5 trigram virtual table synced from the value sidecar by triggers.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class Fts5SubstringIndex implements SubstringIndexInterface
{
    /**
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

    private const MIN_TERM_LENGTH = 3;

    private const VTABLE_SQL = <<<SQL
        CREATE VIRTUAL TABLE IF NOT EXISTS entry_attribute_fts USING fts5(
            value_original,
            content = 'entry_attribute_values',
            content_rowid = 'rowid',
            tokenize = 'trigram'
        )
        SQL;

    private const INSERT_TRIGGER_SQL = <<<SQL
        CREATE TRIGGER IF NOT EXISTS entry_attribute_fts_ai AFTER INSERT ON entry_attribute_values
            WHEN new.attr_name_lower IN (%s)
        BEGIN
            INSERT INTO entry_attribute_fts(rowid, value_original) VALUES (new.rowid, new.value_original);
        END
        SQL;

    private const DELETE_TRIGGER_SQL = <<<SQL
        CREATE TRIGGER IF NOT EXISTS entry_attribute_fts_ad AFTER DELETE ON entry_attribute_values
            WHEN old.attr_name_lower IN (%s)
        BEGIN
            INSERT INTO entry_attribute_fts(entry_attribute_fts, rowid, value_original)
                VALUES ('delete', old.rowid, old.value_original);
        END
        SQL;

    private const MATCH_SQL = <<<SQL
        lc_dn IN (
            SELECT s.entry_lc_dn FROM entry_attribute_values s
            WHERE s.attr_name_lower = ?
              AND s.rowid IN (SELECT rowid FROM entry_attribute_fts WHERE entry_attribute_fts MATCH ?)
        )
        SQL;

    private static ?bool $supported = null;

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

    /**
     * Whether this SQLite build has FTS5 with the trigram tokenizer (compile-time, so a throwaway probe suffices).
     */
    public static function isSupported(): bool
    {
        if (self::$supported !== null) {
            return self::$supported;
        }

        if (!extension_loaded('pdo_sqlite')) {
            return self::$supported = false;
        }

        try {
            $pdo = new PDO('sqlite::memory:');
            $pdo->exec("CREATE VIRTUAL TABLE probe USING fts5(x, tokenize = 'trigram')");

            return self::$supported = true;
        } catch (Throwable) {
            return self::$supported = false;
        }
    }

    public function schemaStatements(PdoDialectInterface $dialect): array
    {
        if ($this->attributes === []) {
            return [];
        }

        $scope = implode(
            ', ',
            array_map(
                static fn(string $attribute): string => "'" . str_replace("'", "''", $attribute) . "'",
                array_keys($this->attributes),
            ),
        );

        return [
            self::VTABLE_SQL,
            sprintf(self::INSERT_TRIGGER_SQL, $scope),
            sprintf(self::DELETE_TRIGGER_SQL, $scope),
        ];
    }

    public function indexes(string $attributeLower): bool
    {
        return isset($this->attributes[$attributeLower]);
    }

    public function maintain(
        string $lcDn,
        Entry $entry,
        callable $execute,
    ): void {
        // The sync triggers index/de-index off the sidecar rows PdoStorage already writes; nothing to do per entry.
    }

    public function buildSubstringPredicate(
        string $attributeLower,
        array $fragments,
    ): ?SqlFilterResult {
        if (!isset($this->attributes[$attributeLower])) {
            return null;
        }

        $terms = [];
        foreach ($fragments as $fragment) {
            if (!Text::isUtf8($fragment) || mb_strlen($fragment, 'UTF-8') < self::MIN_TERM_LENGTH) {
                continue;
            }

            $terms[] = '"' . str_replace('"', '""', $fragment) . '"';
        }

        if ($terms === []) {
            return null;
        }

        return new SqlFilterResult(
            self::MATCH_SQL,
            [$attributeLower, implode(' AND ', $terms)],
            isExact: false,
        );
    }
}
