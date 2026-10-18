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

namespace Tests\Support\FreeDSx\Ldap\Seed;

use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Dn;
use FreeDSx\Ldap\Entry\Entry;

use function base64_encode;
use function count;
use function intdiv;
use function max;
use function min;
use function pack;
use function sha1;
use function sprintf;
use function strtolower;

/**
 * Schema-valid people of a commonly seen size, related through a reporting chain, teams and departments.
 */
final readonly class PersonSeedEntries implements SeedEntryGeneratorInterface
{
    use FillerAttributesTrait;

    private const TEAM_SIZE = 20;

    private const REPORTS_PER_MANAGER = 10;

    private const DEPARTMENTS = [
        'Engineering',
        'Sales',
        'Marketing',
        'Finance',
        'Support',
        'Operations',
        'Legal',
        'Research',
        'Facilities',
        'People',
    ];

    private const GIVEN_NAMES = [
        'Alex',
        'Blake',
        'Casey',
        'Dana',
        'Elliot',
        'Frankie',
        'Gale',
        'Harper',
        'Indigo',
        'Jordan',
        'Kai',
        'Logan',
        'Morgan',
        'Noel',
        'Oakley',
        'Parker',
        'Quinn',
        'Riley',
        'Sage',
        'Taylor',
    ];

    private const SURNAMES = [
        'Anderson',
        'Brooks',
        'Carter',
        'Dawson',
        'Ellis',
        'Fischer',
        'Garcia',
        'Hughes',
        'Iverson',
        'Jensen',
        'Kowalski',
        'Lambert',
        'Moreno',
        'Nakamura',
        'Okafor',
        'Patel',
        'Quintero',
        'Rossi',
        'Schmidt',
        'Tanaka',
    ];

    private const TITLES = [
        'Engineer',
        'Senior Engineer',
        'Analyst',
        'Manager',
        'Director',
        'Coordinator',
        'Specialist',
        'Consultant',
    ];

    /**
     * @var list<array{string, string, string}> City, state and postal code.
     */
    private const LOCATIONS = [
        ['Springfield', 'IL', '62701'],
        ['Portland', 'OR', '97201'],
        ['Austin', 'TX', '73301'],
        ['Madison', 'WI', '53703'],
        ['Raleigh', 'NC', '27601'],
    ];

    public function __construct(private int $fillerAttributes = 0) {}

    public function generate(int $count): iterable
    {
        for ($i = 1; $i <= $count; $i++) {
            yield $this->person($i);
        }

        if ($count === 0) {
            return;
        }

        yield new Entry(
            new Dn(SeedDn::GROUPS),
            new Attribute(
                'objectClass',
                'organizationalUnit',
            ),
            new Attribute(
                'ou',
                'groups',
            ),
        );

        yield from $this->teams($count);
        yield from $this->departments($count);
    }

    public function isSchemaValid(): bool
    {
        return true;
    }

    private function person(int $i): Entry
    {
        $values = [
            ...$this->identity($i),
            ...$this->account($i),
            ...$this->contact($i),
            ...$this->relations($i),
        ];
        $attributes = [];

        foreach ($values as $name => $nameValues) {
            $attributes[] = new Attribute(
                $name,
                ...$nameValues,
            );
        }

        return new Entry(
            new Dn(SeedDn::person($i)),
            ...$attributes,
            ...$this->fillers(
                $i,
                $this->fillerAttributes,
            ),
        );
    }

    /**
     * @return array<string, list<string>>
     */
    private function identity(int $i): array
    {
        $given = $this->givenName($i);
        $surname = $this->surname($i);

        return [
            'objectClass' => ['inetOrgPerson', 'posixAccount', 'shadowAccount'],
            'cn' => ["seed-{$i}"],
            'sn' => [$surname],
            'givenName' => [$given],
            'initials' => [$given[0] . $surname[0]],
            'displayName' => ["{$given} {$surname}"],
            'uid' => ["seed-{$i}"],
            'employeeNumber' => [(string) (100000 + $i)],
            'title' => [self::TITLES[$i % count(self::TITLES)]],
            'ou' => [self::DEPARTMENTS[$this->departmentIndex($i)]],
            'description' => [$this->description($i)],
        ];
    }

    /**
     * @return array<string, list<string>>
     */
    private function account(int $i): array
    {
        return [
            'uidNumber' => [(string) (1000 + $i)],
            'gidNumber' => [(string) (1000 + $this->departmentIndex($i))],
            'homeDirectory' => ["/home/seed-{$i}"],
            'loginShell' => ['/bin/bash'],
            'gecos' => [$this->givenName($i) . ' ' . $this->surname($i)],
            'userPassword' => [$this->password($i)],
            'shadowLastChange' => [(string) (19000 + $i % 365)],
            'shadowMax' => ['99999'],
            'shadowWarning' => ['7'],
        ];
    }

    /**
     * @return array<string, list<string>>
     */
    private function contact(int $i): array
    {
        [$city, $state, $postalCode] = self::LOCATIONS[$i % count(self::LOCATIONS)];
        $street = (100 + $i % 900) . ' Main Street';
        $alias = strtolower($this->givenName($i) . '.' . $this->surname($i));

        return [
            'mail' => [
                "seed-{$i}@foo.bar",
                "{$alias}.{$i}@foo.bar",
            ],
            'telephoneNumber' => [
                $this->phone('010', $i),
                $this->phone('011', $i),
            ],
            'facsimileTelephoneNumber' => [
                $this->phone('020', $i),
            ],
            'street' => [$street],
            'l' => [$city],
            'st' => [$state],
            'postalCode' => [$postalCode],
            'postalAddress' => ["$street\$$city, $state $postalCode"],
            'physicalDeliveryOfficeName' => ['Building ' . ($i % 12 + 1)],
            'postOfficeBox' => ['PO Box ' . (1000 + $i % 9000)],
            'labeledURI' => ["https://foo.bar/~seed-{$i} Home page"],
        ];
    }

    /**
     * @return array<string, list<string>>
     */
    private function relations(int $i): array
    {
        if ($i === 1) {
            return [];
        }

        return ['seeAlso' => [SeedDn::person($this->manager($i))]];
    }

    /**
     * @return iterable<Entry>
     */
    private function teams(int $count): iterable
    {
        for ($first = 1; $first <= $count; $first += self::TEAM_SIZE) {
            $members = [];

            for ($i = $first; $i <= min($first + self::TEAM_SIZE - 1, $count); $i++) {
                $members[] = SeedDn::person($i);
            }
            $team = intdiv($first - 1, self::TEAM_SIZE) + 1;

            yield $this->group(
                "team-{$team}",
                "Team {$team}",
                $members,
            )->add(
                'owner',
                $members[0],
            );
        }
    }

    /**
     * @return iterable<Entry>
     */
    private function departments(int $count): iterable
    {
        $members = [];

        for ($i = 1; $i <= $count; $i++) {
            $members[$this->departmentIndex($i)][] = SeedDn::person($i);
        }

        foreach ($members as $index => $departmentMembers) {
            yield $this->group(
                "dept-{$index}",
                self::DEPARTMENTS[$index],
                $departmentMembers,
            );
        }
    }

    /**
     * @param list<string> $members
     */
    private function group(
        string $cn,
        string $description,
        array $members,
    ): Entry {
        return new Entry(
            new Dn(SeedDn::group($cn)),
            new Attribute(
                'objectClass',
                'groupOfNames',
            ),
            new Attribute(
                'cn',
                $cn,
            ),
            new Attribute(
                'description',
                $description,
            ),
            new Attribute(
                'member',
                ...$members,
            ),
        );
    }

    private function description(int $i): string
    {
        return sprintf(
            '%s %s works in %s as %s from the %s office. This free text stands in for the biography, role summary '
            . 'and notes a directory commonly carries for a person, so the entry is a typical size on the wire.',
            $this->givenName($i),
            $this->surname($i),
            self::DEPARTMENTS[$this->departmentIndex($i)],
            self::TITLES[$i % count(self::TITLES)],
            self::LOCATIONS[$i % count(self::LOCATIONS)][0],
        );
    }

    private function password(int $i): string
    {
        $salt = pack(
            'N',
            $i,
        );
        $digest = sha1(
            'password-' . $i . $salt,
            true,
        );

        return '{SSHA}' . base64_encode($digest . $salt);
    }

    private function phone(
        string $exchange,
        int $i,
    ): string {
        return sprintf(
            '+1 555 %s %04d',
            $exchange,
            $i % 10000,
        );
    }

    private function givenName(int $i): string
    {
        return self::GIVEN_NAMES[$i % count(self::GIVEN_NAMES)];
    }

    private function surname(int $i): string
    {
        return self::SURNAMES[intdiv($i, count(self::GIVEN_NAMES)) % count(self::SURNAMES)];
    }

    private function departmentIndex(int $i): int
    {
        return $i % count(self::DEPARTMENTS);
    }

    /**
     * A manager always has a lower index than its reports and is seeded before them.
     */
    private function manager(int $i): int
    {
        return max(
            1,
            intdiv($i, self::REPORTS_PER_MANAGER),
        );
    }
}
