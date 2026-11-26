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
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkWriteDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoPendingLinkDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\ReferenceIntegrityInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkTarget;
use FreeDSx\Ldap\Server\Backend\Storage\Link\UnresolvedReference;
use Generator;

use function array_chunk;
use function count;
use function is_array;

/**
 * Holds the values a write named but no entry answers to, until one does.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class PendingLinkWriter implements ReferenceIntegrityInterface
{
    use PdoColumnCastTrait;

    /**
     * Parked values per statement. Five placeholders each, inside the 999 bound older SQLite builds compile in.
     */
    private const VALUES_PER_STATEMENT = 200;

    public function __construct(
        private PdoPendingLinkDialectInterface&PdoLinkWriteDialectInterface $dialect,
        private PdoConnection $connection,
    ) {}

    /**
     * Discards what the owner had parked, since a write restates which of its values are unresolved.
     */
    public function clearFor(int $ownerId): void
    {
        $this->connection->execute(
            $this->dialect->queryDeletePendingForOwner(),
            [$ownerId],
        );
    }

    /**
     * Parks the targets naming an entry that is not stored, with the uid each was written with.
     *
     * @param array<string, list<LinkTarget>> $targets
     * @param array<string, int> $resolved Ids of the DNs that did resolve, keyed by their normalised form.
     */
    public function park(
        int $ownerId,
        array $targets,
        array $resolved,
    ): void {
        $pending = [];

        foreach ($targets as $name => $attributeTargets) {
            foreach ($attributeTargets as $target) {
                if (isset($resolved[$target->lcDn])) {
                    continue;
                }

                $pending[] = [
                    $name,
                    $target,
                ];
            }
        }

        if ($pending === []) {
            return;
        }

        foreach (array_chunk($pending, self::VALUES_PER_STATEMENT) as $chunk) {
            $params = [];

            foreach ($chunk as [$name, $target]) {
                $params[] = $ownerId;
                $params[] = $name;
                $params[] = $target->lcDn;
                $params[] = $target->name;
                $params[] = $target->uid;
            }

            $this->connection->execute(
                $this->dialect->queryInsertPending(count($chunk)),
                $params,
            );
        }
    }

    /**
     * Links whatever was parked for a DN that now exists, or for every DN when none is named.
     */
    public function promote(?Dn $landed = null): void
    {
        $byDn = $landed !== null;
        $params = $byDn
            ? [$landed->normalizedString()]
            : [];

        // Nothing parked is the steady state
        // It is answered by an index rather than by the promoting join.
        if ($this->connection->execute($this->dialect->queryAnyPending($byDn), $params)->fetch() === false) {
            return;
        }

        $this->connection->execute(
            $this->dialect->queryPromotePending($byDn),
            $params,
        );
        $this->connection->execute(
            $this->dialect->queryDeletePromotedPending($byDn),
            $params,
        );
    }

    /**
     * The attribute names holding a value that named an entry which is not stored.
     *
     * @return list<string>
     */
    public function unresolvedReferences(Dn $owner): array
    {
        $ownerId = $this->idOf($owner);

        if ($ownerId === null) {
            return [];
        }
        $names = [];

        foreach ($this->rowsOf($this->dialect->queryPendingNamesForOwner(), [$ownerId]) as $row) {
            $names[] = $this->stringColumn($row['attr_name_lower'] ?? null);
        }

        return $names;
    }

    /**
     * The first value still parked, by the order its owner was stored, or null when nothing is.
     */
    public function firstUnresolvedReference(): ?UnresolvedReference
    {
        $rows = $this->rowsOf(
            $this->dialect->queryFirstPending(),
            [],
        );

        foreach ($rows as $row) {
            return new UnresolvedReference(
                new Dn($this->stringColumn($row['dn'] ?? null)),
                $this->stringColumn($row['attr_name_lower'] ?? null),
            );
        }

        return null;
    }

    /**
     * The id the DN is stored under, or null when nothing is stored there.
     */
    private function idOf(Dn $owner): ?int
    {
        foreach ($this->rowsOf($this->dialect->queryResolveDns(1), [$owner->normalizedString()]) as $row) {
            return $this->intColumn($row['entry_id'] ?? null);
        }

        return null;
    }

    /**
     * @param list<string|int> $params
     *
     * @return Generator<int, array<array-key, mixed>>
     */
    private function rowsOf(
        string $sql,
        array $params,
    ): Generator {
        $statement = $this->connection->execute($sql, $params);

        while (($row = $statement->fetch()) !== false) {
            if (is_array($row)) {
                yield $row;
            }
        }
    }
}
