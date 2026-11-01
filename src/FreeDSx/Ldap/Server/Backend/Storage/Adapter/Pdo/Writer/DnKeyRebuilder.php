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

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Exception\InvalidDnSyntaxException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Error\PdoErrorFactory;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\DnKeyRebuilderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnKeyCollisionException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use Generator;
use PDOException;

use function count;
use function is_array;
use function is_string;
use function sprintf;

/**
 * Rebuilds the DN keys stored with entries and parked link targets from the values beside them.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class DnKeyRebuilder implements DnKeyRebuilderInterface
{
    use PdoColumnCastTrait;

    /**
     * Rows read per statement while walking a table.
     */
    private const PAGE_SIZE = 1000;

    /**
     * Starts the placeholder key a row holds while keys pass between rows; no DN normalizes to it.
     */
    private const VACATED_KEY_PREFIX = '#';

    private const SELECT_ENTRIES = <<<SQL
        SELECT entry_id, dn, lc_dn, lc_parent_dn
        FROM entries
        WHERE entry_id > ?
        ORDER BY entry_id
        LIMIT ?
        SQL;

    private const VACATE_ENTRY_KEY = <<<SQL
        UPDATE entries
        SET lc_dn = ?
        WHERE entry_id = ?
        SQL;

    private const REKEY_ENTRY = <<<SQL
        UPDATE entries
        SET lc_dn = ?, lc_parent_dn = ?
        WHERE entry_id = ?
        SQL;

    private const SELECT_DN_BY_KEY = <<<SQL
        SELECT dn
        FROM entries
        WHERE lc_dn = ?
        SQL;

    private const SELECT_PENDING_TARGETS = <<<SQL
        SELECT DISTINCT target_value, target_lc_dn
        FROM entry_link_pending
        SQL;

    private const REKEY_PENDING_TARGET = <<<SQL
        UPDATE entry_link_pending
        SET target_lc_dn = ?
        WHERE target_value = ? AND target_lc_dn = ?
        SQL;

    public function __construct(
        private PdoConnection $connection,
        private PdoErrorFactory $errors,
    ) {}

    public function rebuild(): void
    {
        $this->connection->joinAtomic(function (): void {
            $this->rebuildEntries();
            $this->rebuildPendingTargets();
        });
    }

    /**
     * Each row whose key changes moves aside first, freeing its key for whichever row now needs it.
     *
     * @throws DnKeyCollisionException
     * @throws DnTooLongException
     * @throws InvalidDnSyntaxException
     */
    private function rebuildEntries(): void
    {
        $changed = [];

        foreach ($this->entryRows() as [$entryId, $dn, $lcDn, $parentLcDn]) {
            $stored = self::storedDn($dn);

            if ($stored->lcDn === $lcDn && $stored->parentLcDn === $parentLcDn) {
                continue;
            }
            if ($stored->lcDn !== $lcDn) {
                $this->connection->execute(
                    self::VACATE_ENTRY_KEY,
                    [
                        self::VACATED_KEY_PREFIX . $entryId,
                        $entryId,
                    ],
                );
            }
            $changed[] = [
                $entryId,
                $dn,
                $stored->lcDn,
                $stored->parentLcDn,
            ];
        }

        foreach ($changed as [$entryId, $dn, $lcDn, $parentLcDn]) {
            $this->rekeyEntry(
                $entryId,
                $dn,
                $lcDn,
                $parentLcDn,
            );
        }
    }

    /**
     * @throws DnKeyCollisionException
     * @throws DnTooLongException
     */
    private function rekeyEntry(
        int $entryId,
        string $dn,
        string $lcDn,
        string $parentLcDn,
    ): void {
        $update = fn() => $this->connection->execute(
            self::REKEY_ENTRY,
            [
                $lcDn,
                $parentLcDn,
                $entryId,
            ],
        );

        try {
            $update();
        } catch (PDOException $e) {
            $error = $this->errors->of($e);

            if ($error->isDuplicateDn()) {
                throw new DnKeyCollisionException(
                    $dn,
                    $this->dnHolding($lcDn) ?? $lcDn,
                    $e,
                );
            }
            if ($error->isValueTooLong()) {
                throw new DnTooLongException(
                    sprintf(
                        'The rebuilt DN key of "%s" exceeds the storage backend limit.',
                        $dn,
                    ),
                    $e,
                );
            }

            throw $e;
        }
    }

    /**
     * Parked targets are keyed the way the writer parks them, from the value as it was written.
     */
    private function rebuildPendingTargets(): void
    {
        $statement = $this->connection->execute(self::SELECT_PENDING_TARGETS);
        $targets = [];

        while (($row = $statement->fetch()) !== false) {
            if (is_array($row) && is_string($row['target_value'] ?? null) && is_string($row['target_lc_dn'] ?? null)) {
                $targets[] = [$row['target_value'], $row['target_lc_dn']];
            }
        }

        foreach ($targets as [$value, $lcDn]) {
            $key = (new Dn($value))->normalizedString();

            if ($key === $lcDn) {
                continue;
            }
            $this->connection->execute(
                self::REKEY_PENDING_TARGET,
                [
                    $key,
                    $value,
                    $lcDn,
                ],
            );
        }
    }

    /**
     * Each page is read in full before it is handed over, leaving no statement open while its rows are rewritten.
     *
     * @return Generator<int, array{int, string, string, string}>
     */
    private function entryRows(): Generator
    {
        $after = 0;

        do {
            $statement = $this->connection->execute(
                self::SELECT_ENTRIES,
                [
                    $after,
                    self::PAGE_SIZE,
                ],
            );
            $rows = [];

            while (($row = $statement->fetch()) !== false) {
                $rows[] = $this->entryRow($row);
            }
            unset($statement);

            foreach ($rows as $entryRow) {
                $after = $entryRow[0];

                yield $entryRow;
            }
        } while (count($rows) === self::PAGE_SIZE);
    }

    /**
     * @return array{int, string, string, string}
     */
    private function entryRow(mixed $row): array
    {
        $row = is_array($row)
            ? $row
            : [];

        return [
            $this->intColumn($row['entry_id'] ?? null),
            $this->stringColumn($row['dn'] ?? null),
            $this->stringColumn($row['lc_dn'] ?? null),
            $this->stringColumn($row['lc_parent_dn'] ?? null),
        ];
    }

    /**
     * @throws InvalidDnSyntaxException
     */
    private static function storedDn(string $dn): StoredDn
    {
        try {
            return StoredDn::of(new Dn($dn));
        } catch (InvalidDnSyntaxException $e) {
            throw new InvalidDnSyntaxException(
                sprintf(
                    'The stored DN "%s" is not valid: %s',
                    $dn,
                    $e->getMessage(),
                ),
                $e,
            );
        }
    }

    private function dnHolding(string $lcDn): ?string
    {
        return $this->connection
            ->execute(
                self::SELECT_DN_BY_KEY,
                [$lcDn],
            )
            ->fetchStringColumn();
    }
}
