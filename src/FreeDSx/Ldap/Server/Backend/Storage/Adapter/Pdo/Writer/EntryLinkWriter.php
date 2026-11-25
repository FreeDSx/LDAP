<?php

declare(strict_types=1);

/**
 * This file is part of the FreeDSx LDAP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra @gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Writer;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkWriteDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Dialect\Contract\PdoLinkReadDialectInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Connection\PdoConnection;
use FreeDSx\Ldap\Server\Backend\Storage\Adapter\Pdo\Statement\PdoColumnCastTrait;
use FreeDSx\Ldap\Server\Backend\Storage\Capability\HeldLinkLookupInterface;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkDelta;
use FreeDSx\Ldap\Server\Backend\Storage\Link\LinkTarget;
use FreeDSx\Ldap\Server\Backend\Storage\Schema\LinkedAttributes;
use Generator;

use function array_chunk;
use function array_keys;
use function array_merge;
use function array_values;
use function count;
use function is_array;
use function ksort;

/**
 * Keeps an entry's linked values in the table they are stored in, and answers which of them it links there.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
final readonly class EntryLinkWriter implements HeldLinkLookupInterface
{
    use PdoColumnCastTrait;

    /**
     * Links per statement. Four placeholders each, inside the 999 bound SQLite builds before 3.32 compile in.
     */
    private const LINKS_PER_STATEMENT = 200;

    /**
     * DNs per resolving statement, one placeholder each.
     */
    private const DNS_PER_STATEMENT = 500;

    public function __construct(
        private PdoLinkWriteDialectInterface&PdoLinkReadDialectInterface $dialect,
        private PdoConnection $connection,
        private LinkedAttributes $linked,
        private PendingLinkWriter $pending,
    ) {}

    /**
     * Brings the entry's links to what it now holds, touching only the rows that differ.
     *
     * @throws OperationException when a value carries a uid longer than can be stored
     */
    public function write(
        int $ownerId,
        Entry $entry,
    ): void {
        if ($this->linked->isEmpty()) {
            return;
        }

        $this->restate(
            $ownerId,
            $this->linked->valuesOf($entry),
        );
    }

    /**
     * Brings the owner's links to exactly the values given, touching only the rows that differ.
     *
     * @param array<string, list<string>> $values Values keyed by lowercased attribute name.
     *
     * @throws OperationException when a value carries a uid longer than can be stored
     */
    public function restate(
        int $ownerId,
        array $values,
    ): void {
        $targets = $this->storableTargetsOf($values);
        $resolved = $this->resolve(self::flattened($targets));
        $wanted = $this->wantedLinks(
            $targets,
            $resolved,
        );
        $held = $this->heldLinks($ownerId);

        $this->deleteLinks(
            $ownerId,
            array_diff_key($held, $wanted),
        );
        $this->insertLinks(
            $ownerId,
            array_diff_key($wanted, $held),
        );
        $this->pending->clearFor($ownerId);
        $this->pending->park(
            $ownerId,
            $targets,
            $resolved,
        );
    }

    /**
     * The links of an entry that was just created, which holds nothing yet to diff against or clear.
     *
     * @throws OperationException when a value carries a uid longer than can be stored
     */
    public function writeNew(
        int $ownerId,
        Entry $entry,
    ): void {
        if ($this->linked->isEmpty()) {
            return;
        }
        $values = $this->linked->valuesOf($entry);

        if ($values === []) {
            return;
        }
        $targets = $this->storableTargetsOf($values);
        $resolved = $this->resolve(self::flattened($targets));

        $this->insertLinks(
            $ownerId,
            $this->wantedLinks(
                $targets,
                $resolved,
            ),
        );
        $this->pending->park(
            $ownerId,
            $targets,
            $resolved,
        );
    }

    /**
     * Applies only the values the delta names, leaving whatever else the attribute links untouched.
     *
     * @throws OperationException when an added value carries a uid longer than can be stored
     */
    public function apply(
        int $ownerId,
        LinkDelta $delta,
    ): void {
        $added = [];
        $removed = [];

        foreach ($delta->names() as $name) {
            $added[$name] = $delta->added($name);
            $removed[$name] = $delta->removed($name);
        }
        $added = $this->storableTargetsOf($added);
        $removed = $this->targetsOf($removed);
        $resolved = $this->resolve(array_merge(
            self::flattened($added),
            self::flattened($removed),
        ));

        // Gathered across every attribute first, since a statement per attribute takes index locks in an order that
        // differs between writers, which concurrent writers deadlock on.
        $this->deleteLinks(
            $ownerId,
            $this->wantedLinks(
                $removed,
                $resolved,
            ),
        );
        $this->insertLinks(
            $ownerId,
            $this->wantedLinks(
                $added,
                $resolved,
            ),
        );
        $this->pending->park(
            $ownerId,
            $added,
            $resolved,
        );
    }

    /**
     * Which of the named values the owner links, judged on the same locked targets the write then applies to.
     */
    public function heldLinkValues(
        Dn $owner,
        string $attribute,
        array $values,
    ): array {
        $asked = [];
        $targets = [];

        foreach ($values as $value) {
            $target = $this->linked->targetOf(
                $attribute,
                $value,
            );
            $asked[$target->identity()] = $value;
            $targets[$target->identity()] = $target;
        }
        // Compared by target id rather than by DN, which a rename committing in between could change.
        $resolved = $this->resolve(array_values($targets));

        if ($resolved === []) {
            return [];
        }
        $held = $this->heldTargets(
            $owner,
            $attribute,
            $resolved,
        );
        $found = [];

        foreach ($targets as $identity => $target) {
            if (isset($held[self::linkOf($resolved[$target->lcDn] ?? 0, $target->uid)])) {
                $found[] = $asked[$identity];
            }
        }

        return $found;
    }

    /**
     * Each attribute's values split into the entries they name and the uids they carry.
     *
     * @param array<string, list<string>> $values
     *
     * @return array<string, list<LinkTarget>>
     */
    private function targetsOf(array $values): array
    {
        $targets = [];

        foreach ($values as $name => $attributeValues) {
            foreach ($attributeValues as $value) {
                $targets[$name][] = $this->linked->targetOf(
                    $name,
                    $value,
                );
            }
        }

        return $targets;
    }

    /**
     * The targets of values about to be stored, refused when a uid is longer than the table keeps.
     *
     * @param array<string, list<string>> $values
     *
     * @return array<string, list<LinkTarget>>
     *
     * @throws OperationException
     */
    private function storableTargetsOf(array $values): array
    {
        $targets = $this->targetsOf($values);

        foreach (self::flattened($targets) as $target) {
            $target->assertStorable();
        }

        return $targets;
    }

    /**
     * @param array<string, list<LinkTarget>> $targets
     *
     * @return list<LinkTarget>
     */
    private static function flattened(array $targets): array
    {
        return array_merge(...array_values($targets));
    }

    /**
     * The ids of the DNs the targets name, keyed by their normalized form.
     *
     * @param list<LinkTarget> $targets
     *
     * @return array<string, int>
     */
    private function resolve(array $targets): array
    {
        $wanted = [];

        foreach ($targets as $target) {
            $wanted[$target->lcDn] = true;
        }

        if ($wanted === []) {
            return [];
        }
        $ids = [];

        foreach (array_chunk(array_keys($wanted), self::DNS_PER_STATEMENT) as $chunk) {
            foreach ($this->rowsOf($this->dialect->queryResolveDns(count($chunk)), $chunk) as $row) {
                $ids[$this->stringColumn($row['lc_dn'] ?? null)] = $this->intColumn($row['entry_id'] ?? null);
            }
        }

        return $ids;
    }

    /**
     * The links the owner holds under the attribute to any of the resolved targets, each keyed by target and uid.
     *
     * @param array<string, int> $resolved
     *
     * @return array<string, true>
     */
    private function heldTargets(
        Dn $owner,
        string $attribute,
        array $resolved,
    ): array {
        $held = [];
        $chunks = array_chunk(
            array_values($resolved),
            self::DNS_PER_STATEMENT,
        );

        foreach ($chunks as $chunk) {
            $rows = $this->rowsOf(
                $this->dialect->queryHeldLinkTargets(count($chunk)),
                [
                    $owner->normalizedString(),
                    Attribute::normalizeName($attribute),
                    ...$chunk,
                ],
            );

            foreach ($rows as $row) {
                $held[self::linkOf(
                    $this->intColumn($row['target_entry_id'] ?? null),
                    $this->stringColumn($row['target_uid'] ?? null),
                )] = true;
            }
        }

        return $held;
    }

    /**
     * The links the targets stand for, keyed so that two spellings of one target and uid collapse to one row.
     *
     * @param array<string, list<LinkTarget>> $targets
     * @param array<string, int> $resolved
     *
     * @return array<string, array{string, int, string}>
     */
    private function wantedLinks(
        array $targets,
        array $resolved,
    ): array {
        $links = [];

        foreach ($targets as $name => $attributeTargets) {
            foreach ($attributeTargets as $target) {
                $targetId = $resolved[$target->lcDn] ?? null;

                if ($targetId === null) {
                    continue;
                }

                $key = $this->keyOf(
                    $name,
                    $targetId,
                    $target->uid,
                );
                $links[$key] = [$name, $targetId, $target->uid];
            }
        }

        return $links;
    }

    /**
     * The links already stored for the owner, keyed the same way as the wanted ones.
     *
     * @return array<string, array{string, int, string}>
     */
    private function heldLinks(int $ownerId): array
    {
        $links = [];

        foreach ($this->rowsOf($this->dialect->queryLinkIdsForOwner(), [$ownerId]) as $row) {
            $name = $this->stringColumn($row['attr_name_lower'] ?? null);
            $targetId = $this->intColumn($row['target_entry_id'] ?? null);
            $uid = $this->stringColumn($row['target_uid'] ?? null);

            $links[$this->keyOf($name, $targetId, $uid)] = [$name, $targetId, $uid];
        }

        return $links;
    }

    /**
     * @param array<string, array{string, int, string}> $links
     */
    private function deleteLinks(
        int $ownerId,
        array $links,
    ): void {
        if ($links === []) {
            return;
        }

        // Ordered the same way by every writer, since a statement per attribute takes index locks in an order that
        // differs between them, which concurrent writers deadlock on.
        ksort($links);

        foreach (array_chunk($links, self::LINKS_PER_STATEMENT) as $chunk) {
            $params = [$ownerId];

            foreach ($chunk as [$name, $targetId, $uid]) {
                $params[] = $name;
                $params[] = $targetId;
                $params[] = $uid;
            }

            $this->connection->execute(
                $this->dialect->queryDeleteLinks(count($chunk)),
                $params,
            );
        }
    }

    /**
     * @param array<string, array{string, int, string}> $links
     */
    private function insertLinks(
        int $ownerId,
        array $links,
    ): void {
        if ($links === []) {
            return;
        }
        ksort($links);

        foreach (array_chunk($links, self::LINKS_PER_STATEMENT) as $chunk) {
            $params = [];

            foreach ($chunk as [$name, $targetId, $uid]) {
                $params[] = $ownerId;
                $params[] = $name;
                $params[] = $targetId;
                $params[] = $uid;
            }

            $this->connection->execute(
                $this->dialect->queryInsertLinks(count($chunk)),
                $params,
            );
        }
    }

    private function keyOf(
        string $name,
        int $targetId,
        string $uid,
    ): string {
        return $name . "\0" . self::linkOf(
            $targetId,
            $uid,
        );
    }

    private static function linkOf(
        int $targetId,
        string $uid,
    ): string {
        return $targetId . "\0" . $uid;
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
