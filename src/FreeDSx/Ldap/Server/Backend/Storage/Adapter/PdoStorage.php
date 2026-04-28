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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use Generator;
use PDO;
use PDOStatement;
use Throwable;
use WeakMap;

/**
 * PDO-backed storage; pass a PdoDialectInterface + PdoConnectionProviderInterface, or use SqliteStorage / MysqlStorage factories.
 *
 * When injecting a pre-built PDO, wrap it in SharedPdoConnectionProvider and call PdoStorage::initialize($pdo, $dialect) first.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStorage implements EntryStorageInterface, ResettableInterface
{
    private const STATEMENT_CACHE_MAX = 64;

    /**
     * @var WeakMap<PDO, array<string, list<PDOStatement>>>
     */
    private WeakMap $statementCache;

    public function __construct(
        private readonly PdoConnectionProviderInterface $provider,
        private readonly FilterTranslatorInterface $translator,
        private readonly PdoDialectInterface $dialect,
    ) {
        $this->statementCache = new WeakMap();
    }

    public function reset(): void
    {
        $this->provider->reset();
        $this->statementCache = new WeakMap();
    }

    public static function initialize(
        PDO $pdo,
        PdoDialectInterface $dialect,
    ): void {
        $pdo->setAttribute(
            PDO::ATTR_ERRMODE,
            PDO::ERRMODE_EXCEPTION,
        );
        $pdo->setAttribute(
            PDO::ATTR_DEFAULT_FETCH_MODE,
            PDO::FETCH_ASSOC,
        );

        $pdo->exec($dialect->ddlCreateTable());

        $indexDdl = $dialect->ddlCreateIndex();
        if ($indexDdl !== null) {
            $pdo->exec($indexDdl);
        }

        $pdo->exec($dialect->ddlCreateSidecarTable());

        foreach ($dialect->ddlCreateSidecarIndexes() as $indexSql) {
            $pdo->exec($indexSql);
        }
    }

    public function find(Dn $dn): ?Entry
    {
        $stmt = $this->prepareAndExecute(
            $this->dialect->queryFetchEntry(),
            [$dn->toString()],
        );
        $row = $stmt->fetch();

        return $row !== false
            ? $this->rowToEntry($row)
            : null;
    }

    public function exists(Dn $dn): bool
    {
        $stmt = $this->prepareAndExecute(
            $this->dialect->queryExists(),
            [$dn->toString()],
        );

        return $stmt->fetch() !== false;
    }

    public function list(StorageListOptions $options): EntryStream
    {
        $filterResult = $this->translator->translate($options->filter);
        $isPreFiltered = $filterResult !== null && $filterResult->isExact;

        $sqlLimit = $isPreFiltered && $options->sizeLimit > 0
            ? $options->sizeLimit
            : null;

        $stmt = $this->buildListStatement(
            $options->baseDn->toString(),
            $options->subtree,
            $filterResult,
            $sqlLimit,
        );

        $deadline = $options->timeLimit > 0
            ? microtime(true) + $options->timeLimit
            : null;

        return new EntryStream(
            $this->generateRows($stmt, $deadline),
            $isPreFiltered,
        );
    }

    /**
     * @return Generator<Entry>
     */
    private function generateRows(
        PooledStatement $stmt,
        ?float $deadline,
    ): Generator {
        while (($row = $stmt->fetch()) !== false) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            $entry = $this->rowToEntry($row);
            if ($entry !== null) {
                yield $entry;
            }
        }
    }

    public function store(Entry $entry): void
    {
        $normDn = $entry->getDn()->normalize();
        $dnString = $entry->getDn()->toString();

        $this->assertDnFits($dnString);

        $lcDn = $normDn->toString();

        $this->atomic(function () use ($entry, $lcDn, $dnString, $normDn): void {
            $this->prepareAndExecute($this->dialect->queryUpsert(), [
                $lcDn,
                $dnString,
                $normDn->getParent()?->toString() ?? '',
                $this->encodeAttributes($entry),
            ]);

            $this->prepareAndExecute(
                $this->dialect->querySidecarDelete(),
                [$lcDn],
            );

            $this->insertSidecarRows(
                $lcDn,
                $entry,
            );
        });
    }

    private function insertSidecarRows(
        string $lcDn,
        Entry $entry,
    ): void {
        $rows = $this->buildSidecarRows($lcDn, $entry);
        if ($rows === []) {
            return;
        }

        $tuple = '(?, ?, ?, ?)';
        $placeholders = implode(
            ', ',
            array_fill(0, count($rows), $tuple),
        );
        $params = [];
        foreach ($rows as $row) {
            $params[] = $row[0];
            $params[] = $row[1];
            $params[] = $row[2];
            $params[] = $row[3];
        }

        $this->prepareAndExecute(
            $this->dialect->querySidecarInsertPrefix() . $placeholders,
            $params,
        );
    }

    /**
     * @return list<array{string, string, string, string}> (entry_lc_dn, attr_name_lower, value_lower, value_original)
     */
    private function buildSidecarRows(
        string $lcDn,
        Entry $entry,
    ): array {
        $rows = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attrNameLower = strtolower($attribute->getName());

            foreach ($attribute->getValues() as $value) {
                $rows[] = [
                    $lcDn,
                    $attrNameLower,
                    $this->buildSidecarValueLower($value),
                    $value,
                ];
            }
        }

        return $rows;
    }

    private function buildSidecarValueLower(string $value): string
    {
        if (!mb_check_encoding($value, 'UTF-8')) {
            return '';
        }

        return mb_substr(
            mb_strtolower($value, 'UTF-8'),
            0,
            SqlFilterUtility::MAX_INDEXED_VALUE_CHARS,
            'UTF-8',
        );
    }

    /**
     * @throws DnTooLongException when the DN exceeds the dialect's maximum supported length
     */
    private function assertDnFits(string $dn): void
    {
        $max = $this->dialect->maxDnLength();
        if ($max === null) {
            return;
        }

        $length = strlen($dn);
        if ($length <= $max) {
            return;
        }

        throw new DnTooLongException(
            sprintf(
                'DN length %d exceeds the storage backend limit of %d bytes.',
                $length,
                $max,
            ),
        );
    }

    public function remove(Dn $dn): void
    {
        $this->prepareAndExecute(
            $this->dialect->queryDelete(),
            [$dn->toString()],
        );
    }

    public function hasChildren(Dn $dn): bool
    {
        $stmt = $this->prepareAndExecute(
            $this->dialect->queryHasChildren(),
            [$dn->toString()],
        );

        return $stmt->fetch() !== false;
    }

    public function atomic(callable $operation): void
    {
        $pdo = $this->provider->get();
        $txState = $this->provider->txState();

        $depth = $txState->depth++;
        $savepointCreated = false;
        $transactionStarted = false;

        try {
            if ($depth === 0) {
                $this->dialect->beginTransaction($pdo);
                $transactionStarted = true;
            } else {
                $pdo->exec("SAVEPOINT {$this->savepointName($depth)}");
                $savepointCreated = true;
            }

            $operation($this);

            if ($depth === 0 && $txState->broken) {
                $this->dialect->rollBack($pdo);
            } elseif ($depth === 0) {
                $this->dialect->commit($pdo);
            } else {
                $pdo->exec("RELEASE SAVEPOINT {$this->savepointName($depth)}");
            }
        } catch (Throwable $e) {
            if ($transactionStarted) {
                $this->dialect->rollBack($pdo);
            } elseif ($savepointCreated) {
                $pdo->exec("ROLLBACK TO SAVEPOINT {$this->savepointName($depth)}");
            } elseif ($depth > 0) {
                // Savepoint creation itself failed; the outer transaction is now in an unknown state and must not be committed.
                $txState->broken = true;
            }

            throw $e;
        } finally {
            $txState->depth--;
            if ($txState->depth === 0) {
                $txState->broken = false;
            }
        }
    }

    private function buildListStatement(
        string $base,
        bool $subtree,
        ?SqlFilterResult $filterResult,
        ?int $sizeLimit,
    ): PooledStatement {
        if (!$subtree) {
            return $this->buildChildQuery(
                $base,
                $filterResult,
                $sizeLimit,
            );
        }

        if ($base === '') {
            return $this->buildRootQuery(
                $filterResult,
                $sizeLimit,
            );
        }

        return $this->buildSubtreeQuery(
            $base,
            $filterResult,
            $sizeLimit,
        );
    }

    private function buildChildQuery(
        string $base,
        ?SqlFilterResult $filterResult,
        ?int $sizeLimit,
    ): PooledStatement {
        $sql = $this->dialect->queryFetchChildren();
        $params = [$base];

        if ($filterResult !== null) {
            $sql .= ' AND (' . $filterResult->sql . ')';
            $params = array_merge(
                $params,
                $filterResult->params,
            );
        }

        return $this->prepareAndExecute(
            $sql . $this->buildLimitClause($sizeLimit),
            $params,
        );
    }

    private function buildRootQuery(
        ?SqlFilterResult $filterResult,
        ?int $sizeLimit,
    ): PooledStatement {
        $sql = $this->dialect->queryFetchAll();
        $params = [];

        if ($filterResult !== null) {
            $sql .= ' WHERE (' . $filterResult->sql . ')';
            $params = $filterResult->params;
        }

        return $this->prepareAndExecute(
            $sql . $this->buildLimitClause($sizeLimit),
            $params,
        );
    }

    private function buildSubtreeQuery(
        string $base,
        ?SqlFilterResult $filterResult,
        ?int $sizeLimit,
    ): PooledStatement {
        if ($filterResult !== null) {
            return $this->buildFilteredSubtreeQuery(
                $base,
                $filterResult,
                $sizeLimit,
            );
        }

        return $this->prepareAndExecute(
            $this->dialect->querySubtree() . $this->buildLimitClause($sizeLimit),
            [$base],
        );
    }

    /**
     * Filter drives via the sidecar index; scope suffix is LIKE-checked per candidate.
     */
    private function buildFilteredSubtreeQuery(
        string $base,
        SqlFilterResult $filterResult,
        ?int $sizeLimit,
    ): PooledStatement {
        $fetchAll = $this->dialect->queryFetchAll();
        $filterSql = $filterResult->sql;
        $sql = <<<SQL
            $fetchAll WHERE ($filterSql)
            AND (lc_dn = ? OR lc_dn LIKE ? ESCAPE '!')
            SQL;

        $params = $filterResult->params;
        $params[] = $base;
        $params[] = '%,' . SqlFilterUtility::escape($base);

        return $this->prepareAndExecute(
            $sql . $this->buildLimitClause($sizeLimit),
            $params,
        );
    }

    private function buildLimitClause(?int $sizeLimit): string
    {
        if ($sizeLimit === null) {
            return '';
        }

        return ' LIMIT ' . $sizeLimit;
    }

    private function encodeAttributes(Entry $entry): string
    {
        $attributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attributes[$attribute->getName()] = array_values($attribute->getValues());
        }

        return json_encode(
            $attributes,
            JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR,
        );
    }

    private function rowToEntry(mixed $row): ?Entry
    {
        if (!is_array($row)) {
            return null;
        }

        $dn = isset($row['dn']) && is_string($row['dn'])
            ? $row['dn']
            : '';
        $attributesJson = isset($row['attributes']) && is_string($row['attributes'])
            ? $row['attributes']
            : '{}';

        $raw = json_decode(
            $attributesJson,
            true,
            flags: JSON_THROW_ON_ERROR,
        );

        if (!is_array($raw)) {
            return null;
        }

        $attributes = [];

        foreach ($raw as $name => $values) {
            if (!is_string($name) || !is_array($values)) {
                continue;
            }

            /** @var string[] $values Trusted: written by encodeAttributes() from Attribute::getValues(): string[]. */
            $attributes[] = Attribute::fromArray(
                $name,
                $values,
            );
        }

        return Entry::raw(
            new Dn($dn),
            $attributes,
        );
    }

    /**
     * @param list<string> $params
     */
    private function prepareAndExecute(
        string $query,
        array $params = [],
    ): PooledStatement {
        $pdo = $this->provider->get();
        $pools = $this->statementCache[$pdo] ?? [];

        if (isset($pools[$query]) && $pools[$query] !== []) {
            $pool = $pools[$query];
            $stmt = array_pop($pool);
            $pools[$query] = $pool;
        } else {
            if (!isset($pools[$query]) && count($pools) >= self::STATEMENT_CACHE_MAX) {
                array_shift($pools);
            }

            $stmt = $pdo->prepare($query);
            if ($stmt === false) {
                throw new StorageIoException('Failed to prepare SQL statement.');
            }

            if (!isset($pools[$query])) {
                $pools[$query] = [];
            }
        }

        $this->statementCache[$pdo] = $pools;

        $stmt->execute($params);

        return new PooledStatement(
            $stmt,
            function (PDOStatement $released) use ($pdo, $query): void {
                $this->returnToPool($pdo, $query, $released);
            },
        );
    }

    private function returnToPool(
        PDO $pdo,
        string $query,
        PDOStatement $stmt,
    ): void {
        try {
            $stmt->closeCursor();
        } catch (Throwable) {
            return;
        }

        $pools = $this->statementCache[$pdo] ?? [];
        if (!isset($pools[$query])) {
            return;
        }

        $pools[$query][] = $stmt;
        $this->statementCache[$pdo] = $pools;
    }

    private function savepointName(int $depth): string
    {
        return "sp_{$depth}";
    }
}
