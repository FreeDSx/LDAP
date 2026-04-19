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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\FilterTranslatorInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\SqlFilter\SqlFilterResult;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStorageInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\TimeLimitExceededException;
use FreeDSx\Ldap\Server\Backend\Storage\StorageListOptions;
use Generator;
use JsonException;
use PDO;
use PDOStatement;
use Throwable;

/**
 * PDO-backed storage; pass a PdoDialectInterface + PdoConnectionProviderInterface, or use SqliteStorage / MysqlStorage factories.
 *
 * When injecting a pre-built PDO, wrap it in SharedPdoConnectionProvider and call PdoStorage::initialize($pdo, $dialect) first.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final class PdoStorage implements EntryStorageInterface
{
    public function __construct(
        private readonly PdoConnectionProviderInterface $provider,
        private readonly FilterTranslatorInterface $translator,
        private readonly PdoDialectInterface $dialect,
    ) {
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
        PDOStatement $stmt,
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

        $this->prepareAndExecute($this->dialect->queryUpsert(), [
            $normDn->toString(),
            $dnString,
            $normDn->getParent()?->toString() ?? '',
            $this->encodeAttributes($entry),
        ]);
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

        try {
            if ($depth === 0) {
                $pdo->beginTransaction();
            } else {
                $pdo->exec("SAVEPOINT {$this->savepointName($depth)}");
                $savepointCreated = true;
            }

            $operation($this);

            if ($depth === 0 && $txState->broken) {
                $pdo->rollBack();
            } elseif ($depth === 0) {
                $pdo->commit();
            } else {
                $pdo->exec("RELEASE SAVEPOINT {$this->savepointName($depth)}");
            }
        } catch (Throwable $e) {
            if ($depth === 0 && $pdo->inTransaction()) {
                $pdo->rollBack();
            } elseif ($depth > 0 && $savepointCreated) {
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
    ): PDOStatement {
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
    ): PDOStatement {
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
    ): PDOStatement {
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
    ): PDOStatement {
        $params = [$base];
        $sql = $this->dialect->querySubtree();

        if ($filterResult !== null) {
            $sql .= ' WHERE (' . $filterResult->sql . ')';
            $params = array_merge($params, $filterResult->params);
        }

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
            $attributes[strtolower($attribute->getName())] = [
                'name' => $attribute->getName(),
                'values' => array_values($attribute->getValues()),
            ];
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

        try {
            $raw = json_decode(
                $attributesJson,
                true,
                flags: JSON_THROW_ON_ERROR,
            );
        } catch (JsonException) {
            return null;
        }

        if (!is_array($raw)) {
            return null;
        }

        $attributes = [];

        foreach ($raw as $lcName => $slot) {
            if (!is_string($lcName) || !is_array($slot)) {
                continue;
            }

            $displayName = isset($slot['name']) && is_string($slot['name'])
                ? $slot['name']
                : $lcName;
            $values = isset($slot['values']) && is_array($slot['values'])
                ? $slot['values']
                : [];

            $stringValues = array_values(
                array_filter($values, fn($v) => is_string($v)),
            );
            $attributes[] = new Attribute(
                $displayName,
                ...$stringValues
            );
        }

        return new Entry(
            new Dn($dn),
            ...$attributes
        );
    }

    /**
     * @param list<string> $params
     */
    private function prepareAndExecute(
        string $query,
        array $params = [],
    ): PDOStatement {
        $stmt = $this->provider->get()->prepare($query);
        $stmt->execute($params);

        return $stmt;
    }

    private function savepointName(int $depth): string
    {
        return "sp_{$depth}";
    }
}
