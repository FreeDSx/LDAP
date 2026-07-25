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
use FreeDSx\Ldap\Exception\RuntimeException;
use FreeDSx\Ldap\Schema\Text;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnectionProviderInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\PdoListQueryBuilder;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoTransactor;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoStatementPool;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PooledStatement;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query\SqlQuery;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SidecarLeaf;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\Capture\ChangeJournalingTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalConfig;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\ChangeJournalInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Journal\PdoChangeJournal;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\DnTooLongException;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterUtility;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SubstringIndex\SubstringIndexInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Lock\RowLockableInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use FreeDSx\Ldap\Server\Backend\ResettableInterface;
use Generator;
use PDO;

/**
 * PDO-backed storage; the container builds it from a PdoConfig set via ServerOptions::setStorageConfig().
 *
 * When injecting a pre-built PDO, wrap it in SharedPdoConnectionProvider and call PdoStorage::initialize($pdo, $dialect) first.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStorage implements EntryStorageInterface, ResettableInterface, ChangeJournalingInterface, RowLockableInterface
{
    use ChangeJournalingTrait;

    /**
     * The current schema revision shipped in resources/schema.
     */
    public const SCHEMA_VERSION = 2;

    /**
     * Match ceiling for a composed AND's drivable leaf: below it the leaf is a cheap, complete driver via a near-free probe.
     */
    private const COMPOSED_DRIVER_PROBE_LIMIT = 128;

    private readonly PdoListQueryBuilder $queryBuilder;

    private readonly PdoTransactor $transactor;

    private readonly PdoStatementPool $statements;

    /**
     * @param ?PdoStatementPool $statements Must draw from $provider; defaults to a pool of its own over that connection.
     */
    public function __construct(
        private readonly PdoConnectionProviderInterface $provider,
        private readonly FilterTranslatorInterface $translator,
        private readonly PdoDialectInterface $dialect,
        private readonly ?SubstringIndexInterface $substringIndex = null,
        ?PdoStatementPool $statements = null,
    ) {
        if (!extension_loaded('mbstring')) {
            throw new RuntimeException(
                'The PDO storage backend requires the "mbstring" extension.',
            );
        }

        $this->queryBuilder = new PdoListQueryBuilder($dialect);
        $this->transactor = new PdoTransactor(
            $provider,
            $dialect,
        );
        $this->statements = $statements ?? new PdoStatementPool($provider);
    }

    public function reset(): void
    {
        $this->provider->reset();
        $this->statements->reset();
    }

    public static function initialize(
        PDO $pdo,
        PdoDialectInterface $dialect,
        ?SubstringIndexInterface $substringIndex = null,
    ): void {
        $pdo->setAttribute(
            PDO::ATTR_ERRMODE,
            PDO::ERRMODE_EXCEPTION,
        );
        $pdo->setAttribute(
            PDO::ATTR_DEFAULT_FETCH_MODE,
            PDO::FETCH_ASSOC,
        );

        $statements = [
            ...$dialect->schemaStatements(),
            ...($substringIndex?->schemaStatements($dialect) ?? []),
        ];

        foreach ($statements as $statement) {
            $pdo->exec($statement);
        }
    }

    /**
     * The full schema for a dialect as a runnable SQL script, to export to a file or feed to a migration tool.
     */
    public static function schemaDdl(PdoDialectInterface $dialect): string
    {
        return $dialect->schemaSql();
    }

    public function find(Dn $dn): ?Entry
    {
        $stmt = $this->statements->execute(
            $this->dialect->queryFetchEntry(),
            [$dn->normalize()->toString()],
        );
        $row = $stmt->fetch();

        return $row !== false
            ? $this->rowToEntry($row)
            : null;
    }

    public function exists(Dn $dn): bool
    {
        $stmt = $this->statements->execute(
            $this->dialect->queryExists(),
            [$dn->normalize()->toString()],
        );

        return $stmt->fetch() !== false;
    }

    public function list(StorageListOptions $options): EntryStream
    {
        $deadline = $options->timeLimit > 0
            ? microtime(true) + $options->timeLimit
            : null;

        $filterResult = $this->translator->translate(
            $options->filter,
            $options->isIntegerOrdered(...),
        );

        // A composed filter with a selective drivable leaf streams off that leaf; PHP re-evaluates the full filter.
        $composed = $this->tryComposedStreamingQuery($filterResult, $options);
        if ($composed !== null) {
            return new EntryStream(
                $this->generateRows(
                    $this->statements->execute(
                        $composed->sql,
                        $composed->params,
                    ),
                    $deadline,
                    $options->attributes,
                ),
                false,
            );
        }

        $isPreFiltered = $filterResult !== null && $filterResult->isExact;

        // Exact is bound by the client sizeLimit; otherwise cap candidate transfer at lookthrough+1.
        $sqlLimit = match (true) {
            $isPreFiltered && $options->sizeLimit > 0 => $options->sizeLimit,
            $options->lookthroughLimit > 0 => $options->lookthroughLimit + 1,
            default => null,
        };

        $query = $this->queryBuilder->build(
            $options->baseDn->normalize()->toString(),
            $options->subtree,
            $filterResult,
            $sqlLimit,
            $options->sortKeys,
        );

        return new EntryStream(
            $this->generateRows(
                $this->statements->execute($query->sql, $query->params),
                $deadline,
                $options->attributes,
            ),
            $isPreFiltered,
        );
    }

    public function store(Entry $entry): void
    {
        $normDn = $entry->getDn()->normalize();
        $dnString = $entry->getDn()->toString();

        $this->assertDnFits($dnString);

        $lcDn = $normDn->toString();

        $this->atomic(function () use ($entry, $lcDn, $dnString, $normDn): void {
            $this->statements->execute($this->dialect->queryUpsert(), [
                $lcDn,
                $dnString,
                $normDn->getParent()?->toString() ?? '',
                $this->encodeAttributes($entry),
            ]);

            $this->statements->execute(
                $this->dialect->querySidecarDelete(),
                [$lcDn],
            );

            $this->insertSidecarRows(
                $lcDn,
                $entry,
            );

            $this->substringIndex?->maintain(
                $lcDn,
                $entry,
                function (string $sql, array $params): void {
                    $this->statements->execute(
                        $sql,
                        $params,
                    );
                },
            );
        });
    }

    public function remove(Dn $dn): void
    {
        $this->statements->execute(
            $this->dialect->queryDelete(),
            [$dn->normalize()->toString()],
        );
    }

    public function hasChildren(Dn $dn): bool
    {
        $stmt = $this->statements->execute(
            $this->dialect->queryHasChildren(),
            [$dn->normalize()->toString()],
        );

        return $stmt->fetch() !== false;
    }

    public function namingContexts(): array
    {
        $stmt = $this->statements->execute($this->dialect->queryNamingContexts());

        $contexts = [];
        while (($row = $stmt->fetch()) !== false) {
            if (!is_array($row) || !isset($row['dn']) || !is_string($row['dn'])) {
                continue;
            }
            $contexts[] = (new Dn($row['dn']))->normalize();
        }

        return $contexts;
    }

    public function atomic(callable $operation): void
    {
        $this->transactor->atomic(fn() => $operation($this));
    }

    public function lockForWrite(Dn $dn): void
    {
        $this->dialect->lockRowForWrite(
            $this->transactor->pdo(),
            'entries',
            $dn->normalize()->toString(),
        );
    }

    protected function buildJournal(ChangeJournalConfig $config): ChangeJournalInterface
    {
        return new PdoChangeJournal(
            $this->transactor,
            $this->dialect,
            $this->statements,
            $config->origin,
        );
    }

    /**
     * Drives a composed AND off its most selective drivable leaf, or null when the fast path does not apply.
     */
    private function tryComposedStreamingQuery(
        ?SqlFilterResult $filterResult,
        StorageListOptions $options,
    ): ?SqlQuery {
        if ($filterResult === null || $filterResult->drivableLeaves === []) {
            return null;
        }

        if (!$options->subtree || $options->sortKeys !== []) {
            return null;
        }

        $driver = $this->selectDriverLeaf($filterResult->drivableLeaves);

        if ($driver === null) {
            return null;
        }

        return $this->queryBuilder->buildStreamingQuery(
            $driver->condition,
            $driver->params,
            $options->baseDn->normalize()->toString(),
            self::COMPOSED_DRIVER_PROBE_LIMIT,
        );
    }

    /**
     * The drivable leaf with the fewest matches under the probe cap, or null when every leaf is broader than the cap.
     *
     * @param list<SidecarLeaf> $leaves
     */
    private function selectDriverLeaf(array $leaves): ?SidecarLeaf
    {
        $best = null;
        $bestCount = self::COMPOSED_DRIVER_PROBE_LIMIT;

        foreach ($leaves as $leaf) {
            $count = $this->probeLeafSelectivity($leaf);

            if ($count < $bestCount) {
                $best = $leaf;
                $bestCount = $count;
            }

            if ($bestCount === 0) {
                break;
            }
        }

        return $best;
    }

    /**
     * Counts a leaf's matches up to the probe cap via a near-free bounded index scan.
     */
    private function probeLeafSelectivity(SidecarLeaf $leaf): int
    {
        $limit = self::COMPOSED_DRIVER_PROBE_LIMIT;
        $sql = <<<SQL
            SELECT COUNT(*) AS c FROM (
                SELECT 1 FROM entry_attribute_values s WHERE {$leaf->condition} LIMIT {$limit}
            ) probe
            SQL;

        $row = $this->statements->execute($sql, $leaf->params)->fetch();
        $count = is_array($row)
            ? ($row['c'] ?? 0)
            : 0;

        return is_numeric($count)
            ? (int) $count
            : 0;
    }

    /**
     * @return Generator<Entry>
     */
    /**
     * @param list<string>|null $attributes
     */
    private function generateRows(
        PooledStatement $stmt,
        ?float $deadline,
        ?array $attributes = null,
    ): Generator {
        $allowed = $attributes === null
            ? null
            : array_fill_keys($attributes, true);

        while (($row = $stmt->fetch()) !== false) {
            if ($deadline !== null && microtime(true) >= $deadline) {
                throw new TimeLimitExceededException();
            }

            $entry = $this->rowToEntry(
                $row,
                $allowed,
            );
            if ($entry !== null) {
                yield $entry;
            }
        }
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

        $this->statements->execute(
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
        if (!Text::isUtf8($value)) {
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

    private function encodeAttributes(Entry $entry): string
    {
        $attributes = [];

        foreach ($entry->getAttributes() as $attribute) {
            $attributes[$attribute->getDescription()] = array_values($attribute->getValues());
        }

        return serialize($attributes);
    }

    /**
     * @param array<string, true>|null $allowed Base names to materialize, or null for all.
     */
    private function rowToEntry(
        mixed $row,
        ?array $allowed = null,
    ): ?Entry {
        if (!is_array($row)) {
            return null;
        }

        $dn = isset($row['dn']) && is_string($row['dn'])
            ? $row['dn']
            : '';

        // A projection that materializes nothing, such as a 1.1 request, never reads the blob.
        if ($allowed === []) {
            return Entry::raw(
                new Dn($dn),
                [],
            );
        }

        $attributesBlob = isset($row['attributes']) && is_string($row['attributes'])
            ? $row['attributes']
            : 'a:0:{}';

        /** @var array<string, list<string>>|false $raw Trusted: written by encodeAttributes() from Attribute::getValues(): string[]. */
        $raw = @unserialize(
            $attributesBlob,
            ['allowed_classes' => false],
        );

        if (!is_array($raw)) {
            throw new StorageIoException('Failed to decode entry attributes; storage row is corrupted.');
        }

        $attributes = [];

        foreach ($raw as $name => $values) {
            if ($allowed !== null && !isset($allowed[strtolower((string) strtok($name, ';'))])) {
                continue;
            }

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
}
