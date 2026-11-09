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

use FreeDSx\Asn1\Asn1;
use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Controls;
use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\TlsTestsTrait;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\Protocol\NestedSequenceRequest;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function array_fill;
use function array_map;
use function extension_loaded;
use function range;

/**
 * Behavior that runs against every server runner.
 */
abstract class ServerRunnerTestCase extends ServerTestCase
{
    use TlsTestsTrait;
    use RawClientQueueTrait;

    public static function setUpBeforeClass(): void
    {
        if (!static::isRunnerAvailable()) {
            return;
        }
        parent::setUpBeforeClass();

        static::initSharedServer(
            'ldap-server',
            'tcp',
            static::runnerArgs(),
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

    public function testAnIdleConnectionReceivesANoticeOfDisconnectionOnShutdown(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--shutdown-timeout=10'],
        );

        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new SimpleBindRequest(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ),
        ));
        $queue->getMessage(1);

        $this->sendServerSignal(SIGTERM);
        try {
            $queue->getMessage();
            self::fail('The connection ended without a notice of disconnection.');
        } catch (UnsolicitedNotificationException $e) {
            self::assertTrue($e->isNoticeOfDisconnection());
            self::assertSame(
                ResultCode::UNAVAILABLE,
                $e->getCode(),
            );
        } finally {
            $queue->close();
        }
    }

    public function testASearchFilterNestedPastTheLimitIsRefusedAsUnwillingToPerformAndTheSessionContinues(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH + 1))->base('dc=foo,dc=bar'),
            );
            self::fail('The deeply nested filter should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNWILLING_TO_PERFORM,
                $e->getCode(),
            );
        }

        $entries = $this->ldapClient()->search(
            Operations::search(self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH))->base('dc=foo,dc=bar'),
        );
        self::assertGreaterThan(
            0,
            $entries->count(),
        );
    }

    public function testAnAssertionFilterNestedPastTheLimitIsRefusedAsUnwillingToPerform(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNWILLING_TO_PERFORM);

        $this->ldapClient()->compare(
            'cn=user,dc=foo,dc=bar',
            'cn',
            'user',
            Controls::assertion(self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH + 1)),
        );
    }

    public function testASearchFilterPastTheItemLimitIsRefusedAsAnAdministrativeLimitAndTheSessionContinues(): void
    {
        $this->authenticateUser();

        try {
            $this->ldapClient()->search(
                Operations::search(self::filterOfItems(FilterDecoder::MAX_ITEMS + 1))->base('dc=foo,dc=bar'),
            );
            self::fail('The wide filter should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
        }

        $entries = $this->ldapClient()->search(
            Operations::search(self::filterOfItems(FilterDecoder::MAX_ITEMS))->base('dc=foo,dc=bar'),
        );
        self::assertGreaterThan(
            0,
            $entries->count(),
        );
    }

    public function testASearchFilterOfEmptySetsPastTheItemLimitIsRefusedAsAnAdministrativeLimit(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::or(
                Filters::present('objectClass'),
                ...array_map(
                    static fn(): FilterInterface => Filters::and(),
                    range(
                        1,
                        FilterDecoder::MAX_ITEMS,
                    ),
                ),
            ))->base('dc=foo,dc=bar'),
        );
    }

    public function testASearchFilterPastTheItemLimitIsRefusedBeforeAnyOfItsFiltersIsDecoded(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->search(
            Operations::search(Filters::or(
                self::filterNestedWithin(FilterDecoder::MAX_NESTING_DEPTH + 1),
                ...array_map(
                    static fn(int $i): FilterInterface => Filters::equal(
                        'cn',
                        "absent-{$i}",
                    ),
                    range(
                        1,
                        FilterDecoder::MAX_ITEMS,
                    ),
                ),
            ))->base('dc=foo,dc=bar'),
        );
    }

    public function testAnAssertionFilterPastTheItemLimitIsRefusedAsAnAdministrativeLimit(): void
    {
        $this->authenticateUser();

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::ADMIN_LIMIT_EXCEEDED);

        $this->ldapClient()->compare(
            'cn=user,dc=foo,dc=bar',
            'cn',
            'user',
            Controls::assertion(self::filterOfItems(FilterDecoder::MAX_ITEMS + 1)),
        );
    }

    public function testARequestNestedPastTheDecodeDepthLimitEndsTheSessionWithAProtocolError(): void
    {
        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            new NestedSequenceRequest(20),
        ));

        try {
            $queue->getMessage();
            self::fail('The connection ended without a notice of disconnection.');
        } catch (UnsolicitedNotificationException $e) {
            self::assertTrue($e->isNoticeOfDisconnection());
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        } finally {
            $queue->close();
        }

        self::assertTrue($this->bindsUser($this->buildClient('tcp')));
    }

    public function testARequestOfMoreElementsThanTheLimitEndsTheSessionWithAProtocolError(): void
    {
        $queue = $this->boundRawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            2,
            Operations::modify(
                'cn=user,dc=foo,dc=bar',
                ...array_fill(
                    0,
                    25_000,
                    Change::replace(
                        'description',
                        'x',
                    ),
                ),
            ),
        ));

        try {
            $queue->getMessage();
            self::fail('The connection ended without a notice of disconnection.');
        } catch (UnsolicitedNotificationException $e) {
            self::assertTrue($e->isNoticeOfDisconnection());
            self::assertSame(
                ResultCode::PROTOCOL_ERROR,
                $e->getCode(),
            );
        } finally {
            $queue->close();
        }

        self::assertTrue($this->bindsUser($this->buildClient('tcp')));
    }

    public function testARequestWithinTheElementLimitIsAnswered(): void
    {
        $queue = $this->boundRawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            2,
            Operations::search(
                Filters::present('objectClass'),
                ...array_map(
                    static fn(int $i): string => "attr{$i}",
                    range(
                        1,
                        50_000,
                    ),
                ),
            )->base('dc=foo,dc=bar')->useBaseScope(),
        ));

        try {
            self::assertSame(
                [2 => ResultCode::SUCCESS],
                $this->resultCodesFor(
                    $queue,
                    2,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    public function testASortControlPastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredPastTheElementLimit(
            self::baseSearch(),
            Controls::sort(...array_fill(
                0,
                60_000,
                new SortKey('cn'),
            )),
        );
    }

    public function testAControlsListPastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredPastTheElementLimit(
            self::baseSearch(),
            ...array_fill(
                0,
                60_000,
                new Control('1.2.3.4'),
            ),
        );
    }

    public function testAPasswordModifyValuePastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredPastTheElementLimit(new ExtendedRequest(
            ExtendedRequest::OID_PWD_MODIFY,
            (new LdapEncoder())->encode(Asn1::sequence(...array_fill(
                0,
                120_000,
                Asn1::context(
                    2,
                    Asn1::octetString('x'),
                ),
            ))),
        ));
    }

    public function testTheConnectionLimitHoldsAcrossTheWholeServer(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--max-connections=2'],
        );

        $bound = [];
        for ($i = 0; $i < 6; $i++) {
            $client = $this->buildClient('tcp');
            if ($this->bindsUser($client)) {
                $bound[] = $client;
            }
        }

        self::assertCount(
            2,
            $bound,
        );
    }

    public function testAReloadedAccessPolicyReachesASessionAlreadyOpen(): void
    {
        $this->requirePosix();
        $flagFile = $this->makeFlagFile();
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile],
        );
        $session = $this->buildClient('tcp');
        $session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $before = $session->read('cn=user,dc=foo,dc=bar');
            file_put_contents(
                $flagFile,
                'deny-sn',
            );
            $this->reloadServer();
            $after = $session->read('cn=user,dc=foo,dc=bar');

            self::assertTrue($before?->has('sn'));
            self::assertFalse($after?->has('sn'));
        } finally {
            @unlink($flagFile);
        }
    }

    public function testAPagedSearchContinuesUnderTheReloadedAccessPolicy(): void
    {
        $this->requirePosix();
        $flagFile = $this->makeFlagFile();
        $this->createServerProcess(
            'tcp',
            ['--log', '--reload-flag-file=' . $flagFile, '--entries=10'],
        );
        $session = $this->buildClient('tcp');
        $session->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );
        $paging = $session->paging(
            Operations::search(Filters::startsWith('cn', 'entry-'))->base('dc=foo,dc=bar'),
            5,
        );

        try {
            $before = $paging->getEntries()->toArray();
            file_put_contents(
                $flagFile,
                'deny-sn',
            );
            $this->reloadServer();
            $after = $paging->getEntries()->toArray();

            self::assertSame(
                [5, 5],
                [count($before), count($this->withSn($before))],
            );
            self::assertSame(
                [5, 0],
                [count($after), count($this->withSn($after))],
            );
        } finally {
            @unlink($flagFile);
        }
    }

    /**
     * Appends the runner selection to every server this suite starts, including the per-test ones.
     *
     * @param list<string> $extraArgs
     */
    protected function createServerProcess(
        string $transport,
        array $extraArgs = [],
    ): void {
        parent::createServerProcess(
            $transport,
            [...$extraArgs, ...static::runnerArgs()],
        );
    }

    protected function reloadServer(): void
    {
        $this->sendServerSignal(SIGHUP);
        $this->waitForServerOutput('Server configuration reloaded');
    }

    protected function makeFlagFile(): string
    {
        $flagFile = sys_get_temp_dir() . '/freedsx_runner_reload_' . uniqid('', true);
        file_put_contents(
            $flagFile,
            '',
        );

        return $flagFile;
    }

    /**
     * Hook for subclasses to name the runner the server runs under.
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

    protected function bindsUser(LdapClient $client): bool
    {
        try {
            $client->sendAndReceive(Operations::bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ));
        } catch (ConnectionException) {
            return false;
        }

        return true;
    }

    private function boundRawQueue(): ClientQueue
    {
        $queue = $this->rawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            1,
            Operations::bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ),
        ));
        $queue->getMessage(1);

        return $queue;
    }

    private function assertAnsweredPastTheElementLimit(
        RequestInterface $request,
        Control ...$controls,
    ): void {
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                $request,
                ...$controls,
            ));
            self::assertSame(
                [2 => ResultCode::ADMIN_LIMIT_EXCEEDED],
                $this->resultCodesFor(
                    $queue,
                    2,
                ),
            );

            $queue->sendMessage(new LdapMessageRequest(
                3,
                self::baseSearch(),
            ));
            self::assertSame(
                [3 => ResultCode::SUCCESS],
                $this->resultCodesFor(
                    $queue,
                    3,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    private static function baseSearch(): SearchRequest
    {
        return Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useBaseScope();
    }

    private static function filterNestedWithin(int $depth): FilterInterface
    {
        $filter = Filters::present('objectClass');
        for ($i = 0; $i < $depth; $i++) {
            $filter = Filters::not($filter);
        }

        return $filter;
    }

    /**
     * An OR whose first item matches every entry and whose others name values no entry holds.
     */
    private static function filterOfItems(int $count): FilterInterface
    {
        return Filters::or(
            Filters::present('objectClass'),
            ...array_map(
                static fn(int $i): FilterInterface => Filters::equal(
                    'cn',
                    "absent-{$i}",
                ),
                range(
                    2,
                    $count,
                ),
            ),
        );
    }

    /**
     * @param Entry[] $entries
     * @return Entry[]
     */
    private function withSn(array $entries): array
    {
        return array_filter(
            $entries,
            static fn(Entry $entry): bool => $entry->has('sn'),
        );
    }
}
