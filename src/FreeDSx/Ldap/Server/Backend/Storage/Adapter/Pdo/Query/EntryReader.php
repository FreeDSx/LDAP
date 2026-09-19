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

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Query;

use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\PdoDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryLinks;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\EntryRowCodec;
use FreeDSx\Ldap\Server\Backend\Storage\Exception\StorageIoException;

/**
 * Reads single entries, and the facts about one.
 *
 * @internal
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
readonly class EntryReader
{
    public function __construct(
        private PdoConnection $connection,
        private PdoDialectInterface $dialect,
        private EntryRowCodec $codec,
        private EntryLinks $links,
    ) {}

    /**
     * The stored entry with its linked values resolved, or null when there is none.
     *
     * @throws StorageIoException when the stored row cannot be decoded
     */
    public function find(Dn $dn): ?Entry
    {
        $row = $this->connection
            ->execute(
                $this->dialect->queryFetchEntry(),
                [$dn->normalize()->toString()],
            )
            ->fetch();

        if (!is_array($row)) {
            return null;
        }

        return $this->codec->decode(
            $row,
            null,
            $this->linksFor($row),
        );
    }

    public function exists(Dn $dn): bool
    {
        return $this->connection
            ->execute(
                $this->dialect->queryExists(),
                [$dn->normalize()->toString()],
            )
            ->fetch() !== false;
    }

    public function hasChildren(Dn $dn): bool
    {
        return $this->connection
            ->execute(
                $this->dialect->queryHasChildren(),
                [$dn->normalize()->toString()],
            )
            ->fetch() !== false;
    }

    /**
     * Entries whose parent is not stored, which is what makes them the roots of the directory.
     *
     * @return list<Dn>
     */
    public function namingContexts(): array
    {
        $stmt = $this->connection->execute($this->dialect->queryNamingContexts());
        $contexts = [];

        while (($row = $stmt->fetch()) !== false) {
            if (!is_array($row) || !isset($row['dn']) || !is_string($row['dn'])) {
                continue;
            }
            $contexts[] = (new Dn($row['dn']))->normalize();
        }

        return $contexts;
    }

    /**
     * One entry's links, keyed by attribute name, or none when nothing is declared or the row carries no key.
     *
     * @param array<array-key, mixed> $row
     * @return array<string, list<string>>
     */
    private function linksFor(array $row): array
    {
        if (!$this->links->hydrates(null)) {
            return [];
        }

        $entryId = $row['entry_id'] ?? null;

        return is_int($entryId) || is_string($entryId)
            ? $this->links->forEntry((int) $entryId)
            : [];
    }
}
