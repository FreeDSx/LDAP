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

namespace Tests\Integration\FreeDSx\Ldap\Sync;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Attribute;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncEntryResult;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\SyncRepl;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

/**
 * End-to-end RFC 4533 refreshOnly sync against the built-in FreeDSx server.
 */
final class SyncReplNativeTest extends ServerTestCase
{
    use RawClientQueueTrait;

    private const SEED_LDIF = __DIR__ . '/../../resources/seed/sync-seed.ldif';

    /**
     * Content the visibility tests sync, apart from what the other tests poll and count.
     */
    private const AREA = 'ou=area,dc=other,dc=test';

    private const HIDDEN = 'ou=hidden,' . self::AREA;

    public static function setUpBeforeClass(): void
    {
        parent::setUpBeforeClass();

        if (!extension_loaded('pcntl')) {
            return;
        }

        static::initSharedServer(
            'ldap-server',
            'tcp',
            [
                '--seed=' . self::SEED_LDIF,
                '--allow-sync',
                '--hide-from-sync=' . self::HIDDEN,
            ],
        );
    }

    public static function tearDownAfterClass(): void
    {
        parent::tearDownAfterClass();
        static::tearDownSharedServer();
    }

    public function setUp(): void
    {
        $this->setServerMode('ldap-server');

        parent::setUp();
    }

    public function testItStreamsEveryEntryOnAFreshRefreshOnlyPoll(): void
    {
        $this->authenticateUser();

        $dns = $this->collectPoll(
            $this->syncRepl(),
        );
        sort($dns);

        // A cookieless poll runs the present phase: the whole subtree comes across, nothing more.
        self::assertSame(
            [
                'cn=admin,dc=foo,dc=bar',
                'cn=alice,ou=people,dc=foo,dc=bar',
                'cn=bob,ou=people,dc=foo,dc=bar',
                'cn=carol,ou=people,dc=foo,dc=bar',
                'cn=lockme,ou=people,dc=foo,dc=bar',
                'cn=resetme,ou=people,dc=foo,dc=bar',
                'cn=sync-policy,ou=people,dc=foo,dc=bar',
                'cn=user,dc=foo,dc=bar',
                'dc=foo,dc=bar',
                'ou=people,dc=foo,dc=bar',
            ],
            $dns,
        );
    }

    public function testTheSyncDoneControlIsSentAsNonCritical(): void
    {
        $queue = $this->rawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                Operations::bind(
                    'cn=user,dc=foo,dc=bar',
                    '12345',
                ),
            ));
            $queue->getMessage(1);

            $queue->sendMessage(new LdapMessageRequest(
                2,
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                new SyncRequestControl(),
            ));
            do {
                $message = $queue->getMessage(2);
            } while (!$message->getResponse() instanceof SearchResultDone);

            $syncDone = $message->controls()->get(Control::OID_SYNC_DONE);
            self::assertNotNull($syncDone);
            self::assertFalse($syncDone->getCriticality());
        } finally {
            $queue->close();
        }
    }

    /**
     * @return iterable<string, array{FilterInterface}>
     */
    public static function filterMatchingNothingProvider(): iterable
    {
        yield 'the absolute false' => [Filters::or()];
        yield 'a filter on a withheld attribute' => [Filters::present('userPassword')];
    }

    #[DataProvider('filterMatchingNothingProvider')]
    public function testARefreshMatchingNothingStillEndsWithTheSyncDoneControl(FilterInterface $filter): void
    {
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                Operations::search($filter)
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                new SyncRequestControl(),
            ));
            do {
                $message = $queue->getMessage(2);
            } while (!$message->getResponse() instanceof SearchResultDone);

            self::assertNotNull($message->controls()->get(Control::OID_SYNC_DONE));
        } finally {
            $queue->close();
        }
    }

    /**
     * @return iterable<string, array{Control, int}>
     */
    public static function assertionProvider(): iterable
    {
        yield 'a critical assertion that fails' => [
            Controls::assertion(Filters::equal(
                'dc',
                'nope',
            )),
            ResultCode::ASSERTION_FAILED,
        ];
        yield 'a critical assertion that holds' => [
            Controls::assertion(Filters::equal(
                'dc',
                'foo',
            )),
            ResultCode::SUCCESS,
        ];
        yield 'a non-critical assertion that fails' => [
            Controls::assertion(
                Filters::equal(
                    'dc',
                    'nope',
                ),
                false,
            ),
            ResultCode::ASSERTION_FAILED,
        ];
    }

    #[DataProvider('assertionProvider')]
    public function testASyncSearchHonorsTheAssertionControl(
        Control $assertion,
        int $resultCode,
    ): void {
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useSubtreeScope(),
                new SyncRequestControl(),
                $assertion,
            ));
            do {
                $message = $queue->getMessage(2);
            } while (!$message->getResponse() instanceof SearchResultDone);

            self::assertSame(
                $resultCode,
                $message->getResponse()->getResultCode(),
            );
        } finally {
            $queue->close();
        }
    }

    public function testAPollWithAFilterOnlyStreamsMatchingEntries(): void
    {
        $this->authenticateUser();

        $dns = $this->collectPoll(
            $this->syncRepl(Filters::equal('objectClass', 'organizationalUnit')),
        );

        self::assertSame(
            ['ou=people,dc=foo,dc=bar'],
            $dns,
        );
    }

    public function testAnIncrementalPollWithACookieReturnsOnlyChangesSinceTheCookie(): void
    {
        // Writes below need an administrator, who also holds the privileged sync control.
        $this->authenticateAdmin();

        $cookie = null;
        $initial = $this->syncRepl();
        $initial->useCookieHandler(function (string $value) use (&$cookie): void {
            $cookie = $value;
        });
        $initial->poll();

        self::assertNotNull(
            $cookie,
            'The refresh phase must hand back a cookie for the next poll.',
        );

        $this->ldapClient()->create(Entry::fromArray(
            'cn=dave,ou=people,dc=foo,dc=bar',
            [
                'cn' => 'dave',
                'sn' => 'Davis',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $incremental = $this->syncRepl();
        $incremental->useCookie($cookie);
        $dns = $this->collectPoll($incremental);

        // Only the entry added after the cookie is streamed; the untouched baseline is not resent.
        self::assertSame(
            ['cn=dave,ou=people,dc=foo,dc=bar'],
            $dns,
        );
    }

    public function testAnEntryMovedWhereTheSyncIdentityCannotSearchIsDeletedWhereItWas(): void
    {
        $dn = 'cn=hidee,' . self::AREA;
        $this->createHiddenArea();
        $this->asAdmin(static fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            $dn,
            [
                'cn' => 'hidee',
                'sn' => 'Hidden',
                'objectClass' => 'inetOrgPerson',
            ],
        )));
        $cookie = $this->cookieAfterAFullPollOf(self::AREA);

        $this->asAdmin(static fn(LdapClient $admin) => $admin->move(
            $dn,
            self::HIDDEN,
        ));
        $incremental = $this->syncRepl(baseDn: self::AREA);
        $incremental->useCookie($cookie);

        self::assertSame(
            [$dn],
            $this->collectDeletedDns($incremental),
        );
    }

    public function testASubtreeMovedWhereTheSyncIdentityCannotSearchIsDeletedWithItsChildren(): void
    {
        $ou = 'ou=movers,' . self::AREA;
        $this->createHiddenArea();
        $uuids = $this->asAdmin(static function (LdapClient $admin) use ($ou): array {
            $admin->create(Entry::fromArray(
                $ou,
                [
                    'ou' => 'movers',
                    'objectClass' => 'organizationalUnit',
                ],
            ));

            foreach (['one', 'two'] as $name) {
                $admin->create(Entry::fromArray(
                    'cn=' . $name . ',' . $ou,
                    [
                        'cn' => $name,
                        'sn' => 'Mover',
                        'objectClass' => 'inetOrgPerson',
                    ],
                ));
            }

            return array_map(
                static fn(string $dn): string => (string) $admin->read(
                    $dn,
                    ['entryUUID'],
                )?->get('entryUUID')?->firstValue(),
                [$ou, 'cn=one,' . $ou, 'cn=two,' . $ou],
            );
        });
        $cookie = $this->cookieAfterAFullPollOf(self::AREA);

        $this->asAdmin(static fn(LdapClient $admin) => $admin->move(
            $ou,
            self::HIDDEN,
        ));
        $incremental = $this->syncRepl(baseDn: self::AREA);
        $incremental->useCookie($cookie);
        $deleted = $this->collectDeletedUuids($incremental);
        sort($uuids);
        sort($deleted);

        self::assertSame(
            $uuids,
            $deleted,
        );
    }

    public function testAnEntryLeavingTheContentFromWhereTheSyncIdentityCannotSearchIsNeverNamed(): void
    {
        $dn = 'cn=secret-name,' . self::HIDDEN;
        $this->createHiddenArea();
        $uuid = $this->asAdmin(static function (LdapClient $admin) use ($dn): string {
            $admin->create(Entry::fromArray(
                $dn,
                [
                    'cn' => 'secret-name',
                    'sn' => 'Hidden',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));

            return (string) $admin->read(
                $dn,
                ['entryUUID'],
            )?->get('entryUUID')?->firstValue();
        });
        $cookie = $this->cookieAfterAFullPollOf(self::AREA);

        $this->asAdmin(static fn(LdapClient $admin) => $admin->move(
            $dn,
            'dc=other,dc=test',
        ));
        $incremental = $this->syncRepl(baseDn: self::AREA);
        $incremental->useCookie($cookie);
        $named = $this->collectNamed($incremental);

        self::assertNotContains(
            strtolower($dn),
            $named,
        );
        self::assertNotContains(
            $uuid,
            $named,
        );
    }

    public function testAnEntryMovedIntoTheContentAndThenHiddenIsDeletedWhereItWasVisible(): void
    {
        $dn = 'cn=arrival,dc=other,dc=test';
        $this->createHiddenArea();
        $this->asAdmin(static fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            $dn,
            [
                'cn' => 'arrival',
                'sn' => 'Arrival',
                'objectClass' => 'inetOrgPerson',
            ],
        )));
        $cookie = $this->cookieAfterAFullPollOf(self::AREA);

        $this->asAdmin(static function (LdapClient $admin) use ($dn): void {
            $admin->move(
                $dn,
                self::AREA,
            );
            $admin->move(
                'cn=arrival,' . self::AREA,
                self::HIDDEN,
            );
        });
        $incremental = $this->syncRepl(baseDn: self::AREA);
        $incremental->useCookie($cookie);

        self::assertSame(
            ['cn=arrival,' . self::AREA],
            $this->collectDeletedDns($incremental),
        );
    }

    public function testAnEntryLeavingTheFilterAfterAMoveOutOfAHiddenPlaceNeverNamesTheHiddenDn(): void
    {
        $hiddenDn = 'cn=unfiltered,' . self::HIDDEN;
        $filter = Filters::equal(
            'description',
            'keep',
        );
        $this->createHiddenArea();
        $this->asAdmin(static fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            $hiddenDn,
            [
                'cn' => 'unfiltered',
                'sn' => 'Unfiltered',
                'description' => 'keep',
                'objectClass' => 'inetOrgPerson',
            ],
        )));
        $cookie = $this->cookieAfterAFullPollOf(
            self::AREA,
            $filter,
        );

        $this->asAdmin(static function (LdapClient $admin) use ($hiddenDn): void {
            $admin->move(
                $hiddenDn,
                self::AREA,
            );
            $admin->sendAndReceive(Operations::modify(
                'cn=unfiltered,' . self::AREA,
                Change::replace(
                    'description',
                    'drop',
                ),
            ));
        });
        $incremental = $this->syncRepl(
            $filter,
            self::AREA,
        );
        $incremental->useCookie($cookie);

        self::assertNotContains(
            strtolower($hiddenDn),
            $this->collectNamed($incremental),
        );
    }

    public function testAModifyOutOfTheFilterThenADeleteSendsTheDelete(): void
    {
        $dn = 'cn=dropped,' . self::AREA;
        $filter = Filters::equal(
            'description',
            'keep',
        );
        $this->createHiddenArea();
        $this->asAdmin(static fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            $dn,
            [
                'cn' => 'dropped',
                'sn' => 'Dropped',
                'description' => 'keep',
                'objectClass' => 'inetOrgPerson',
            ],
        )));
        $cookie = $this->cookieAfterAFullPollOf(
            self::AREA,
            $filter,
        );

        $this->asAdmin(static function (LdapClient $admin) use ($dn): void {
            $admin->sendAndReceive(Operations::modify(
                $dn,
                Change::replace(
                    'description',
                    'drop',
                ),
            ));
            $admin->delete($dn);
        });
        $incremental = $this->syncRepl(
            $filter,
            self::AREA,
        );
        $incremental->useCookie($cookie);

        self::assertSame(
            [strtolower($dn)],
            $this->collectDeletedDns($incremental),
        );
    }

    public function testAnEntryMovedOutOfTheContentAndDeletedThereIsDeletedWhereItWasVisible(): void
    {
        $dn = 'cn=leaver,' . self::AREA;
        $this->createHiddenArea();
        $this->asAdmin(static fn(LdapClient $admin) => $admin->create(Entry::fromArray(
            $dn,
            [
                'cn' => 'leaver',
                'sn' => 'Leaver',
                'objectClass' => 'inetOrgPerson',
            ],
        )));
        $cookie = $this->cookieAfterAFullPollOf(self::AREA);

        $this->asAdmin(static function (LdapClient $admin) use ($dn): void {
            $admin->move(
                $dn,
                'dc=other,dc=test',
            );
            $admin->delete('cn=leaver,dc=other,dc=test');
        });
        $incremental = $this->syncRepl(baseDn: self::AREA);
        $incremental->useCookie($cookie);

        self::assertSame(
            [$dn],
            $this->collectDeletedDns($incremental),
        );
    }

    public function testACookieReusedForDifferentContentFallsBackToAFullRefresh(): void
    {
        $this->authenticateAdmin();

        $cookie = null;
        $initial = $this->syncRepl();
        $initial->useCookieHandler(function (string $value) use (&$cookie): void {
            $cookie = $value;
        });
        $initial->poll();

        self::assertNotNull($cookie);

        $this->ldapClient()->create(Entry::fromArray(
            'cn=erin,ou=people,dc=foo,dc=bar',
            [
                'cn' => 'erin',
                'sn' => 'Evans',
                'objectClass' => 'inetOrgPerson',
            ],
        ));

        $narrowed = $this->syncRepl(Filters::equal('objectClass', 'organizationalUnit'));
        $narrowed->useCookie($cookie);

        // An incremental resume would answer with the delta alone, which holds nothing matching the
        // new filter. The whole content of the narrowed search proves the cookie was refused.
        self::assertSame(
            ['ou=people,dc=foo,dc=bar'],
            $this->collectPoll($narrowed),
        );
    }

    public function testAPollDefaultsToEveryUserAndOperationalAttribute(): void
    {
        $this->authenticateUser();

        $entries = $this->collectEntries($this->syncRepl());
        $alice = $entries['cn=alice,ou=people,dc=foo,dc=bar'] ?? null;

        self::assertNotNull($alice);
        self::assertNotNull(
            $alice->get('cn'),
            'A user attribute must come across by default.',
        );
        self::assertNotNull(
            $alice->get('entryUUID'),
            'An operational attribute must come across by default, so a replica is a faithful copy.',
        );
    }

    public function testAPollHonoursAnExplicitAttributeSelection(): void
    {
        $this->authenticateUser();

        $syncRepl = $this->syncRepl();
        $syncRepl->request()->select('cn');

        $entries = $this->collectEntries($syncRepl);
        $alice = $entries['cn=alice,ou=people,dc=foo,dc=bar'] ?? null;

        self::assertNotNull($alice);
        self::assertSame(
            ['cn'],
            array_map(
                static fn(Attribute $attribute): string => $attribute->getDescription(),
                $alice->getAttributes(),
            ),
        );
    }

    public function testAnIncrementalPollReturnsTheBacklinksItSelectsOnAChangedEntry(): void
    {
        $member = $this->seedGroupMember('incr-selected');

        $entries = $this->pollAfterAChangeTo(
            $member,
            'cn',
            'memberOf',
        );

        self::assertSame(
            [$member],
            array_keys($entries),
        );
        self::assertSame(
            ['cn=incr-selected-group,dc=foo,dc=bar'],
            ($entries[$member] ?? null)?->get('memberOf')?->getValues(),
        );
    }

    public function testAnIncrementalPollLeavesOutTheBacklinksItDoesNotSelect(): void
    {
        $member = $this->seedGroupMember('incr-unselected');

        $entries = $this->pollAfterAChangeTo(
            $member,
            'cn',
        );

        self::assertSame(
            [$member],
            array_keys($entries),
        );
        self::assertNull(($entries[$member] ?? null)?->get('memberOf'));
    }

    public function testASyncWithAMalformedBaseDnIsRefused(): void
    {
        $this->authenticateUser();

        $syncRepl = $this->ldapClient()->syncRepl();
        $syncRepl->request()
            ->base('cn=#0C03616263,dc=foo,dc=bar')
            ->useSubtreeScope();

        try {
            $syncRepl->poll();
            self::fail('Expected the sync to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::INVALID_DN_SYNTAX,
                $e->getCode(),
            );
        }
    }

    private function syncRepl(
        ?FilterInterface $filter = null,
        string $baseDn = 'dc=foo,dc=bar',
    ): SyncRepl {
        $syncRepl = $this->ldapClient()->syncRepl($filter);
        $syncRepl->request()
            ->base($baseDn)
            ->useSubtreeScope();

        return $syncRepl;
    }

    /**
     * @return list<string>
     */
    private function collectPoll(SyncRepl $syncRepl): array
    {
        $dns = [];
        $syncRepl->poll(function (SyncEntryResult $result) use (&$dns): void {
            $dns[] = strtolower($result->getEntry()->getDn()->toString());
        });

        return $dns;
    }

    private function createHiddenArea(): void
    {
        $this->asAdmin(static function (LdapClient $admin): void {
            if ($admin->read(self::HIDDEN) !== null) {
                return;
            }

            foreach ([self::AREA => 'area', self::HIDDEN => 'hidden'] as $dn => $ou) {
                $admin->create(Entry::fromArray(
                    $dn,
                    [
                        'ou' => $ou,
                        'objectClass' => 'organizationalUnit',
                    ],
                ));
            }
        });
    }

    private function cookieAfterAFullPollOf(
        string $baseDn,
        ?FilterInterface $filter = null,
    ): string {
        $cookie = null;
        $initial = $this->syncRepl(
            $filter,
            $baseDn,
        );
        $initial->useCookieHandler(function (string $value) use (&$cookie): void {
            $cookie = $value;
        });
        $initial->poll();

        self::assertNotNull(
            $cookie,
            'The refresh phase must hand back a cookie for the next poll.',
        );

        return $cookie;
    }

    /**
     * @return list<string>
     */
    private function collectDeletedDns(SyncRepl $syncRepl): array
    {
        $dns = [];
        $syncRepl->poll(function (SyncEntryResult $result) use (&$dns): void {
            if ($result->isDelete()) {
                $dns[] = strtolower($result->getEntry()->getDn()->toString());
            }
        });

        return $dns;
    }

    /**
     * @return list<string>
     */
    private function collectDeletedUuids(SyncRepl $syncRepl): array
    {
        $uuids = [];
        $syncRepl->useIdSetHandler(function (SyncIdSetResult $result) use (&$uuids): void {
            if (!$result->isDeleted()) {
                return;
            }

            foreach ($result->getDecodedEntryUuids() as $uuid) {
                $uuids[] = $uuid;
            }
        });
        $syncRepl->poll(function (SyncEntryResult $result) use (&$uuids): void {
            if ($result->isDelete()) {
                $uuids[] = $result->getDecodedEntryUuid();
            }
        });

        return $uuids;
    }

    /**
     * Every DN and entryUUID a poll names, whether in an entry or in a set of UUIDs.
     *
     * @return list<string>
     */
    private function collectNamed(SyncRepl $syncRepl): array
    {
        $named = [];
        $syncRepl->useIdSetHandler(function (SyncIdSetResult $result) use (&$named): void {
            foreach ($result->getDecodedEntryUuids() as $uuid) {
                $named[] = $uuid;
            }
        });
        $syncRepl->poll(function (SyncEntryResult $result) use (&$named): void {
            $named[] = strtolower($result->getEntry()->getDn()->toString());
            $named[] = $result->getDecodedEntryUuid();
        });

        return $named;
    }

    /**
     * A new entry and a group naming it, returning the entry's DN.
     */
    private function seedGroupMember(string $name): string
    {
        $member = "cn={$name},ou=people,dc=foo,dc=bar";

        $this->asAdmin(static function (LdapClient $admin) use ($name, $member): void {
            $admin->create(Entry::fromArray(
                $member,
                [
                    'cn' => $name,
                    'sn' => 'Member',
                    'objectClass' => 'inetOrgPerson',
                ],
            ));
            $admin->create(Entry::fromArray(
                "cn={$name}-group,dc=foo,dc=bar",
                [
                    'cn' => "{$name}-group",
                    'member' => $member,
                    'objectClass' => 'groupOfNames',
                ],
            ));
        });

        return $member;
    }

    /**
     * What a poll resumed from a cookie returns once the entry changes after it, both polls selecting the same.
     *
     * @return array<string, Entry>
     */
    private function pollAfterAChangeTo(
        string $dn,
        string ...$attributes,
    ): array {
        $cookie = null;
        $initial = $this->syncRepl();
        $initial->request()->select(...$attributes);
        $initial->useCookieHandler(function (string $value) use (&$cookie): void {
            $cookie = $value;
        });
        $initial->poll();

        self::assertNotNull(
            $cookie,
            'The refresh phase must hand back a cookie for the next poll.',
        );

        $this->asAdmin(static fn(LdapClient $admin) => $admin->sendAndReceive(Operations::modify(
            $dn,
            Change::replace(
                'description',
                'changed',
            ),
        )));

        $incremental = $this->syncRepl();
        $incremental->request()->select(...$attributes);
        $incremental->useCookie($cookie);

        return $this->collectEntries($incremental);
    }

    /**
     * @return array<string, Entry>
     */
    private function collectEntries(SyncRepl $syncRepl): array
    {
        $entries = [];
        $syncRepl->poll(function (SyncEntryResult $result) use (&$entries): void {
            $entries[strtolower($result->getEntry()->getDn()->toString())] = $result->getEntry();
        });

        return $entries;
    }
}
