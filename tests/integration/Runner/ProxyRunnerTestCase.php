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

namespace Tests\Integration\FreeDSx\Ldap\Runner;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sync\SyncRequestControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Response\SearchResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Sync\Result\SyncIdSetResult;
use FreeDSx\Ldap\Sync\SyncRepl;
use PHPUnit\Framework\Attributes\DataProvider;
use RuntimeException;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\RequestBudgetTestsTrait;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\DripsRequestsTrait;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function array_map;
use function extension_loaded;
use function microtime;
use function range;
use function sort;
use function strtolower;
use function usleep;

/**
 * Proxy behavior that runs against every server runner.
 */
abstract class ProxyRunnerTestCase extends ServerTestCase
{
    use RawClientQueueTrait;
    use DripsRequestsTrait;
    use RequestBudgetTestsTrait;

    public static function setUpBeforeClass(): void
    {
        if (!static::isRunnerAvailable()) {
            return;
        }
        parent::setUpBeforeClass();

        static::initSharedServer(
            'ldap-proxy',
            'tcp',
            [
                ...static::runnerArgs(),
                '--upstream-allow-sync',
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
        $this->setServerMode('ldap-proxy');

        parent::setUp();
    }

    public function testItForwardsABoundSearchToTheUpstream(): void
    {
        $this->authenticateUser();

        self::assertCount(
            12,
            $this->ldapClient()->search(
                Operations::search(Filters::equal('sn', 'Entry'))->base('dc=foo,dc=bar'),
            ),
        );
    }

    public function testAClientThatStopsReadingIsClosedAsAWriteTimeoutAndOthersAreStillServed(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--log',
                '--write-timeout=2',
                '--entries=300',
                '--entry-padding=65536',
            ],
        );

        $stalled = $this->boundRawQueue();
        $stalled->sendMessage(new LdapMessageRequest(
            2,
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
        ));

        try {
            $this->waitForServerOutput('The connection was closed because the client stopped reading.');
        } finally {
            $stalled->close();
        }

        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('dc=foo,dc=bar'));
    }

    public function testARequestThatTakesTooLongToArriveEndsTheSessionAndOthersAreStillServed(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--log',
                '--request-read-timeout=2',
            ],
        );

        $closedAfter = $this->dripRequestUntilClosed(
            'tcp',
            8.0,
        );

        self::assertNotNull($closedAfter);
        self::assertLessThan(
            4.0,
            $closedAfter,
        );
        $this->waitForServerOutput('The connection was closed because a request took too long to arrive.');
        $this->authenticateUser();
        self::assertNotNull($this->ldapClient()->read('dc=foo,dc=bar'));
    }

    public function testASessionClosedWithoutAnUnbindReleasesItsUpstreamConnection(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--upstream-max-connections=2'],
        );

        foreach (range(
            1,
            3,
        ) as $ignored) {
            $this->boundRawQueue()->close();
        }
        $this->bindOnceTheUpstreamHasRoom();

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testAnIncrementalSyncPollThroughTheProxyReportsDeletedEntries(): void
    {
        $this->authenticateUser();
        $dns = [
            'cn=proxy-sync-a,dc=foo,dc=bar',
            'cn=proxy-sync-b,dc=foo,dc=bar',
        ];
        $uuids = $this->asAdmin(fn(LdapClient $admin): array => array_map(
            fn(string $dn): string => $this->createPerson(
                $admin,
                $dn,
            ),
            $dns,
        ));
        $cookie = null;
        $this->syncRepl()
            ->useCookieHandler(static function (string $value) use (&$cookie): void {
                $cookie = $value;
            })
            ->poll();
        $this->asAdmin(static function (LdapClient $admin) use ($dns): void {
            foreach ($dns as $dn) {
                $admin->delete($dn);
            }
        });

        $deleted = [];
        $this->syncRepl()
            ->useCookie($cookie)
            ->useIdSetHandler(static function (SyncIdSetResult $result) use (&$deleted): void {
                foreach ($result->getDecodedEntryUuids() as $uuid) {
                    $deleted[] = strtolower($uuid);
                }
            })
            ->poll();

        sort($uuids);
        sort($deleted);
        self::assertSame(
            $uuids,
            $deleted,
        );
        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testACriticalPersistentSyncThroughTheProxyIsRefusedAndTheSessionStaysUsable(): void
    {
        $this->authenticateUser();

        try {
            $this->syncRepl()
                ->useRefreshDoneHandler(static function (): void {
                    throw new RuntimeException('The persistent sync reached its persist stage through the proxy.');
                })
                ->listen();
            self::fail('A persistent sync through the proxy was expected to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                $e->getCode(),
            );
        }

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    #[DataProvider('searchOpenForChangesProvider')]
    public function testASearchKeptOpenForChangesThroughTheProxyIsRefusedByTheProxy(string $oid): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->sendAndReceive(
                Operations::search(Filters::present('objectClass'))
                    ->base('dc=foo,dc=bar')
                    ->useBaseScope(),
                new Control(
                    $oid,
                    true,
                ),
            );
            self::fail('A search kept open for changes through the proxy was expected to be refused.');
        } catch (OperationException $e) {
            self::assertSame(
                [
                    ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
                    'A search that stays open for changes cannot be proxied.',
                ],
                [
                    $e->getCode(),
                    $e->getMessage(),
                ],
            );
        }

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function searchOpenForChangesProvider(): iterable
    {
        yield 'a persistent search' => [Control::OID_PERSISTENT_SEARCH];
        yield 'a change notification' => [Control::OID_CHANGE_NOTIFICATION];
    }

    public function testANonCriticalPersistentSyncThroughTheProxyRunsAsAPlainSearch(): void
    {
        $this->authenticateUser();

        $response = $this->ldapClient()->sendAndReceive(
            Operations::search(Filters::present('objectClass'))
                ->base('dc=foo,dc=bar')
                ->useBaseScope()
                ->useIntermediateResponseHandler(static function (): void {
                    throw new RuntimeException('The search reached the upstream as a persistent sync.');
                }),
            (new SyncRequestControl(SyncRequestControl::MODE_REFRESH_AND_PERSIST))->setCriticality(false),
        );

        $search = $response->getResponse();
        self::assertInstanceOf(
            SearchResponse::class,
            $search,
        );
        self::assertCount(
            1,
            $search->getEntries(),
        );
        self::assertFalse($response->controls()->has(Control::OID_SYNC_DONE));
    }

    /**
     * Appends the runner selection to every proxy this suite starts, including the per-test ones.
     *
     * @param list<string> $extraArgs
     */
    protected function createServerProcess(
        string $transport,
        array $extraArgs = [],
        ?int $openFileLimit = null,
    ): void {
        parent::createServerProcess(
            $transport,
            [...$extraArgs, ...static::runnerArgs()],
            $openFileLimit,
        );
    }

    /**
     * Hook for subclasses to name the runner the proxy runs under.
     *
     * @return list<string>
     */
    protected static function runnerArgs(): array
    {
        return [];
    }

    /**
     * Whether this runner can run here, which the pcntl one cannot without process control.
     */
    protected static function isRunnerAvailable(): bool
    {
        return extension_loaded('pcntl')
            && extension_loaded('posix');
    }

    /**
     * A sync over the whole test directory.
     */
    private function syncRepl(): SyncRepl
    {
        $syncRepl = $this->ldapClient()->syncRepl();
        $syncRepl->request()
            ->base('dc=foo,dc=bar')
            ->useSubtreeScope();

        return $syncRepl;
    }

    /**
     * Creates a person and returns the entryUUID the upstream gave it.
     */
    private function createPerson(
        LdapClient $admin,
        string $dn,
    ): string {
        $entry = Entry::fromArray(
            $dn,
            [
                'sn' => 'Sync',
                'objectClass' => 'inetOrgPerson',
            ],
        );
        $entry->add(
            'cn',
            $entry->getDn()->getRdn()->getValue(),
        );
        $admin->create($entry);
        $uuid = $admin->read(
            $dn,
            ['entryUUID'],
        )?->get('entryUUID')?->firstValue();
        self::assertIsString($uuid);

        return strtolower($uuid);
    }

    /**
     * Binds as the standard user, retrying while the upstream refuses the connection for want of room.
     */
    private function bindOnceTheUpstreamHasRoom(): void
    {
        $deadline = microtime(true) + 5.0;

        while (true) {
            try {
                $this->authenticateUser();

                return;
            } catch (BindException $e) {
                if ($e->getCode() !== ResultCode::UNAVAILABLE || microtime(true) >= $deadline) {
                    throw $e;
                }
                usleep(100_000);
            }
        }
    }
}
