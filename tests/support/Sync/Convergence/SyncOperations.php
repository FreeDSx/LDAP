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

namespace Tests\Support\FreeDSx\Ldap\Sync\Convergence;

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\ModifyDnRequest;
use FreeDSx\Ldap\Operation\Request\ModifyRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operations;
use Random\Randomizer;
use RuntimeException;

use function array_filter;
use function array_map;
use function array_values;
use function count;
use function in_array;
use function sprintf;

/**
 * Picks writes at random from what the provider holds, leaning on the moves and reused DNs a replica finds hardest.
 */
final readonly class SyncOperations
{
    private const PEOPLE = ['alice', 'bob', 'carl', 'dana', 'erin'];

    private const UNITS = ['a', 'b', 'c'];

    private const GROUPS = ['g1', 'g2', 'g3'];

    private const SWAP_NAME = 'swap';

    private const MEMBER = 'member';

    public function __construct(
        private Randomizer $random,
        private ConvergenceProvider $provider,
    ) {}

    /**
     * The layout every run starts from.
     *
     * @return list<RequestInterface>
     */
    public static function layout(): array
    {
        $base = ConvergenceProvider::BASE;
        $alice = 'cn=alice,ou=a,' . $base;
        $bob = 'cn=bob,ou=a,' . $base;
        $carl = 'cn=carl,ou=b,' . $base;
        $erin = 'cn=erin,ou=b,' . $base;

        return [
            Operations::add(Entry::fromArray(
                $base,
                [
                    'objectClass' => ['domain'],
                    'dc' => 'example',
                ],
            )),
            self::unit('ou=a,' . $base),
            self::unit('ou=b,' . $base),
            self::unit(ConvergenceProvider::HIDDEN),
            self::unit('ou=groups,' . $base),
            self::person($alice),
            self::person($bob),
            self::person($carl),
            self::person($erin),
            self::person('cn=dana,' . ConvergenceProvider::HIDDEN),
            self::group(
                'cn=g1,ou=groups,' . $base,
                $alice,
                $bob,
            ),
            self::group(
                'cn=g2,ou=groups,' . $base,
                $carl,
                $erin,
            ),
            self::group(
                'cn=g3,ou=a,' . $base,
                $alice,
                $carl,
                $erin,
            ),
        ];
    }

    /**
     * The writes of one random change, several when it reuses a DN or swaps two names.
     *
     * @return list<RequestInterface>
     */
    public function next(): array
    {
        $entries = $this->provider->entries();

        return match ($this->index(12)) {
            0 => [$this->addPerson($entries)],
            1 => [$this->addUnit($entries)],
            2 => [Operations::delete($this->pick($this->below($entries))->getDn()->toString())],
            3 => [$this->modify($entries)],
            4 => [$this->rename($this->pick($this->below($entries)))],
            5 => [$this->move($entries)],
            6, 7, 8 => [$this->membership($entries)],
            9 => $this->reuse($entries),
            10 => $this->renameAndReuse($entries),
            default => $this->swap($entries),
        };
    }

    /**
     * @param list<Entry> $entries
     */
    private function addPerson(array $entries): AddRequest
    {
        return self::person(sprintf(
            'cn=%s,%s',
            $this->pickName(self::PEOPLE),
            $this->pick($this->containers($entries))->getDn()->toString(),
        ));
    }

    /**
     * @param list<Entry> $entries
     */
    private function addUnit(array $entries): AddRequest
    {
        return self::unit(sprintf(
            'ou=%s,%s',
            $this->pickName(self::UNITS),
            $this->pick($this->containers($entries))->getDn()->toString(),
        ));
    }

    /**
     * @param list<Entry> $entries
     */
    private function modify(array $entries): ModifyRequest
    {
        return Operations::modify(
            $this->pick($this->below($entries))->getDn(),
            Change::replace(
                'description',
                (string) $this->index(1000),
            ),
        );
    }

    private function rename(Entry $entry): ModifyDnRequest
    {
        $rdn = $entry->getDn()->getRdn();

        return Operations::rename(
            $entry->getDn(),
            $rdn->getName() . '=' . $this->pickName($this->namesFor($rdn->getName())),
        );
    }

    /**
     * @param list<Entry> $entries
     */
    private function move(array $entries): ModifyDnRequest
    {
        return Operations::move(
            $this->pick($this->below($entries))->getDn(),
            $this->pick($this->containers($entries))->getDn(),
        );
    }

    /**
     * Adds a person to a group, or takes them out when the group already names them.
     *
     * @param list<Entry> $entries
     */
    private function membership(array $entries): ModifyRequest
    {
        $groups = $this->ofClass(
            $entries,
            'groupOfNames',
        );
        $people = $this->ofClass(
            $entries,
            'person',
        );

        if ($groups === [] || $people === []) {
            return $this->modify($entries);
        }
        $group = $this->pick($groups);

        return Operations::modify(
            $group->getDn(),
            $this->memberChange(
                $group,
                $this->pick($people)->getDn()->toString(),
            ),
        );
    }

    private function memberChange(
        Entry $group,
        string $person,
    ): Change {
        $named = array_map(
            Dn::normalized(...),
            $group->get(self::MEMBER)?->getValues() ?? [],
        );
        $isNamed = in_array(
            Dn::normalized($person),
            $named,
            true,
        );

        return $isNamed
            ? Change::delete(
                self::MEMBER,
                $person,
            )
            : Change::add(
                self::MEMBER,
                $person,
            );
    }

    /**
     * Deletes a person and adds a new one at the same DN.
     *
     * @param list<Entry> $entries
     *
     * @return list<RequestInterface>
     */
    private function reuse(array $entries): array
    {
        $dn = $this->pick($this->peopleOr($entries))->getDn()->toString();

        return [
            Operations::delete($dn),
            self::person($dn),
        ];
    }

    /**
     * Renames a person and adds a new one at the DN it left.
     *
     * @param list<Entry> $entries
     *
     * @return list<RequestInterface>
     */
    private function renameAndReuse(array $entries): array
    {
        $person = $this->pick($this->peopleOr($entries));

        return [
            $this->rename($person),
            self::person($person->getDn()->toString()),
        ];
    }

    /**
     * Swaps the names of two siblings, or renames an entry that has none.
     *
     * @param list<Entry> $entries
     *
     * @return list<RequestInterface>
     */
    private function swap(array $entries): array
    {
        $first = $this->pick($this->below($entries));
        $siblings = $this->siblingsOf(
            $first,
            $entries,
        );

        return $siblings === []
            ? [$this->rename($first)]
            : $this->swapThrough(
                $first->getDn(),
                $this->pick($siblings)->getDn(),
            );
    }

    /**
     * Renames the first aside, the second to the first's name, then the first to the second's.
     *
     * @return list<RequestInterface>
     */
    private function swapThrough(
        Dn $first,
        Dn $second,
    ): array {
        $aside = $first->getRdn()->getName() . '=' . self::SWAP_NAME;

        return [
            Operations::rename(
                $first,
                $aside,
            ),
            Operations::rename(
                $second,
                $first->getRdn()->toString(),
            ),
            Operations::rename(
                $aside . ',' . $first->getParent()?->toString(),
                $second->getRdn()->toString(),
            ),
        ];
    }

    /**
     * @param list<Entry> $entries
     *
     * @return list<Entry>
     */
    private function siblingsOf(
        Entry $entry,
        array $entries,
    ): array {
        $parent = $entry->getDn()->getParent()?->normalize()->toString();
        $name = $entry->getDn()->getRdn()->getName();

        return array_values(array_filter(
            $entries,
            static fn(Entry $other): bool => $other !== $entry
                && $other->getDn()->getParent()?->normalize()->toString() === $parent
                && $other->getDn()->getRdn()->getName() === $name,
        ));
    }

    /**
     * Every entry but the base, which no write may touch.
     *
     * @param list<Entry> $entries
     *
     * @return list<Entry>
     */
    private function below(array $entries): array
    {
        $below = array_values(array_filter(
            $entries,
            static fn(Entry $entry): bool => $entry->getDn()->count() > 2,
        ));

        return $below === []
            ? throw new RuntimeException('The provider holds nothing below its base.')
            : $below;
    }

    /**
     * The base and every unit, which is where a new or moved entry can go.
     *
     * @param list<Entry> $entries
     *
     * @return list<Entry>
     */
    private function containers(array $entries): array
    {
        $base = array_filter(
            $entries,
            static fn(Entry $entry): bool => $entry->getDn()->count() === 2,
        );

        return [
            ...array_values($base),
            ...$this->ofClass(
                $entries,
                'organizationalUnit',
            ),
        ];
    }

    /**
     * @param list<Entry> $entries
     *
     * @return list<Entry>
     */
    private function peopleOr(array $entries): array
    {
        $people = $this->ofClass(
            $entries,
            'person',
        );

        return $people === []
            ? $this->below($entries)
            : $people;
    }

    /**
     * @param list<Entry> $entries
     *
     * @return list<Entry>
     */
    private function ofClass(
        array $entries,
        string $objectClass,
    ): array {
        return array_values(array_filter(
            $entries,
            static fn(Entry $entry): bool => $entry->get('objectClass')?->has(
                $objectClass,
                caseSensitive: false,
            ) ?? false,
        ));
    }

    /**
     * @return list<string>
     */
    private function namesFor(string $rdnName): array
    {
        return $rdnName === 'ou'
            ? self::UNITS
            : [...self::PEOPLE, ...self::GROUPS];
    }

    /**
     * @param list<string> $names
     */
    private function pickName(array $names): string
    {
        return $names[$this->index(count($names))];
    }

    /**
     * @param list<Entry> $entries
     */
    private function pick(array $entries): Entry
    {
        return $entries[$this->index(count($entries))];
    }

    /**
     * A random position in a list of the given length.
     */
    private function index(int $count): int
    {
        return $this->random->getInt(
            0,
            $count - 1,
        );
    }

    private static function person(string $dn): AddRequest
    {
        $name = (new Dn($dn))->getRdn()->getValue();

        return Operations::add(Entry::fromArray(
            $dn,
            [
                'objectClass' => ['person'],
                'cn' => $name,
                'sn' => $name,
            ],
        ));
    }

    private static function unit(string $dn): AddRequest
    {
        return Operations::add(Entry::fromArray(
            $dn,
            [
                'objectClass' => ['organizationalUnit'],
                'ou' => (new Dn($dn))->getRdn()->getValue(),
            ],
        ));
    }

    private static function group(
        string $dn,
        string ...$members,
    ): AddRequest {
        return Operations::add(Entry::fromArray(
            $dn,
            [
                'objectClass' => ['groupOfNames'],
                'cn' => (new Dn($dn))->getRdn()->getValue(),
                self::MEMBER => $members,
            ],
        ));
    }
}
