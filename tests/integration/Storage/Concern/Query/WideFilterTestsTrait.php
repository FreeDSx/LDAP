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

namespace Tests\Integration\FreeDSx\Ldap\Storage\Concern\Query;

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;

/**
 * Filters of tens of thousands of items, answered by a server with PHP's default memory limit.
 */
trait WideFilterTestsTrait
{
    private const WIDE_FILTER_ITEMS = 80_000;

    public function testAVeryWideOrMatchesTheEntriesItNames(): void
    {
        $this->startWideFilterServer();
        $items = $this->absentUidItems();
        $items[40_000] = Filters::equal(
            'uid',
            'wide-1',
        );
        $items[] = Filters::equal(
            'uid',
            'wide-3',
        );

        self::assertEqualsCanonicalizing(
            [
                'uid=wide-1,ou=wide,dc=foo,dc=bar',
                'uid=wide-3,ou=wide,dc=foo,dc=bar',
            ],
            $this->wideSearch(Filters::or(...$items)),
        );
    }

    public function testAVeryWideAndMatchesTheEntriesItLeavesIn(): void
    {
        $this->startWideFilterServer();
        $items = array_map(
            static fn(FilterInterface $item): FilterInterface => Filters::not($item),
            $this->absentUidItems(),
        );

        self::assertEqualsCanonicalizing(
            [
                'uid=wide-1,ou=wide,dc=foo,dc=bar',
                'uid=wide-3,ou=wide,dc=foo,dc=bar',
            ],
            $this->wideSearch(Filters::and(
                Filters::equal(
                    'objectClass',
                    'inetOrgPerson',
                ),
                Filters::not(Filters::equal(
                    'uid',
                    'wide-2',
                )),
                ...$items,
            )),
        );
    }

    /**
     * The arguments that route the server at the backend under test.
     *
     * @return list<string>
     */
    abstract protected static function storageExtraArgs(): array;

    private function startWideFilterServer(): void
    {
        $this->stopServer();
        $this->createServerProcess(
            'tcp',
            [
                ...static::storageExtraArgs(),
                '--memory-limit=128M',
            ],
        );
        $this->authenticateUser();

        $this->asAdmin(static function (LdapClient $admin): void {
            $admin->create(Entry::fromArray(
                'ou=wide,dc=foo,dc=bar',
                [
                    'objectClass' => 'organizationalUnit',
                    'ou' => 'wide',
                ],
            ));

            foreach (['wide-1', 'wide-2', 'wide-3'] as $uid) {
                $admin->create(Entry::fromArray(
                    "uid={$uid},ou=wide,dc=foo,dc=bar",
                    [
                        'objectClass' => 'inetOrgPerson',
                        'uid' => $uid,
                        'cn' => $uid,
                        'sn' => 'Wide',
                    ],
                ));
            }
        });
    }

    /**
     * @return list<FilterInterface>
     */
    private function absentUidItems(): array
    {
        return array_map(
            static fn(int $i): FilterInterface => Filters::equal(
                'uid',
                "absent-{$i}",
            ),
            range(
                1,
                self::WIDE_FILTER_ITEMS,
            ),
        );
    }

    /**
     * @return array<string>
     */
    private function wideSearch(FilterInterface $filter): array
    {
        return array_map(
            static fn(Entry $entry): string => $entry->getDn()->toString(),
            $this->ldapClient()->search(
                Operations::search(
                    $filter,
                    '1.1',
                )
                    ->base('ou=wide,dc=foo,dc=bar')
                    ->useSubtreeScope(),
            )->toArray(),
        );
    }
}
