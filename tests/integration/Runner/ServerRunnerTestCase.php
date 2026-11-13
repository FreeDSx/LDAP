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
use FreeDSx\Ldap\Exception\BindException;
use FreeDSx\Ldap\Exception\ConnectionException;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SaslBindRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\Decoder\AttributeSelectionDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Control\SortingControlDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Filter\FilterDecoder;
use FreeDSx\Ldap\Protocol\Decoder\Request\ModifyRequestDecoder;
use FreeDSx\Ldap\Protocol\Decoder\RequestMessageDecoder;
use FreeDSx\Ldap\Protocol\LdapEncoder;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filter\FilterInterface;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Integration\FreeDSx\Ldap\Runner\Concern\TlsTestsTrait;
use Tests\Integration\FreeDSx\Ldap\ServerTestCase;
use Tests\Support\FreeDSx\Ldap\DripsRequestsTrait;
use Tests\Support\FreeDSx\Ldap\Protocol\NestedSequenceRequest;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;
use Tests\Support\FreeDSx\Ldap\TestWorker;

use function array_fill;
use function array_map;
use function extension_loaded;
use function microtime;
use function range;
use function str_repeat;
use function substr_count;

/**
 * Behavior that runs against every server runner.
 */
abstract class ServerRunnerTestCase extends ServerTestCase
{
    use TlsTestsTrait;
    use RawClientQueueTrait;
    use DripsRequestsTrait;

    /**
     * Enough files to start and serve a few clients, and far fewer than the clients a test opens.
     */
    protected const OPEN_FILE_LIMIT = 64;

    /**
     * Seconds a write may stall in the stalled-reader test.
     */
    private const STALLED_WRITE_TIMEOUT = 3;

    /**
     * Seconds a request may take to arrive in the dripped-request test.
     */
    private const REQUEST_READ_TIMEOUT = 2;

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

    public function testASearchSelectingAsManyAttributesAsTheLimitAllowsIsAnswered(): void
    {
        $queue = $this->boundRawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            2,
            self::searchSelecting(AttributeSelectionDecoder::MAX_ATTRIBUTES),
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

    public function testARequestPastTheAnonymousSizeLimitEndsASessionWithoutABind(): void
    {
        $this->assertASearchPastTheAnonymousSizeEndsTheSession(
            $this->rawQueue(),
            1,
        );
    }

    public function testARequestPastTheAnonymousSizeLimitEndsASessionThatRebindsAnonymously(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--allow-anonymous'],
        );
        $queue = $this->boundRawQueue();
        $queue->sendMessage(new LdapMessageRequest(
            2,
            Operations::bindAnonymously(),
        ));
        self::assertSame(
            [2 => ResultCode::SUCCESS],
            $this->resultCodesFor(
                $queue,
                2,
            ),
        );

        $this->assertASearchPastTheAnonymousSizeEndsTheSession(
            $queue,
            3,
        );
    }

    public function testARequestPastTheAnonymousSizeLimitIsAnsweredOnceTheSessionBinds(): void
    {
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                self::searchPastTheAnonymousSize(),
            ));
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

    public function testASearchSelectingMoreAttributesThanTheLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            self::searchSelecting(AttributeSelectionDecoder::MAX_ATTRIBUTES + 1),
        );
    }

    public function testASortControlPastTheKeyLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            self::baseSearch(),
            Controls::sort(...array_fill(
                0,
                SortingControlDecoder::MAX_KEYS + 1,
                new SortKey('cn'),
            )),
        );
    }

    public function testARequestCarryingMoreControlsThanTheLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            self::baseSearch(),
            ...array_fill(
                0,
                RequestMessageDecoder::MAX_CONTROLS + 1,
                new Control('1.2.3.4'),
            ),
        );
    }

    public function testAPostReadControlSelectingMoreAttributesThanTheLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
            Operations::modify(
                'cn=user,dc=foo,dc=bar',
                Change::replace(
                    'description',
                    'x',
                ),
            ),
            Controls::postRead(...self::attributeNames(AttributeSelectionDecoder::MAX_ATTRIBUTES + 1)),
        );
    }

    public function testAControlsListPastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(
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
        $this->assertAnsweredAsAnAdministrativeLimit(new ExtendedRequest(
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

    public function testAModifyPastTheChangeLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->assertAnsweredAsAnAdministrativeLimit(Operations::modify(
            'cn=user,dc=foo,dc=bar',
            ...array_fill(
                0,
                ModifyRequestDecoder::MAX_CHANGES + 1,
                Change::replace(
                    'description',
                    'x',
                ),
            ),
        ));
    }

    public function testABindPastTheElementLimitLeavesTheSessionAnonymous(): void
    {
        $client = $this->buildClient('tcp');
        $client->bind(
            'cn=user,dc=foo,dc=bar',
            '12345',
        );

        try {
            $client->sendAndReceive(
                Operations::bind(
                    'cn=user,dc=foo,dc=bar',
                    '12345',
                ),
                ...array_fill(
                    0,
                    60_000,
                    new Control('1.2.3.4'),
                ),
            );
            self::fail('The bind was accepted past the element limit.');
        } catch (BindException $e) {
            self::assertSame(
                ResultCode::ADMIN_LIMIT_EXCEEDED,
                $e->getCode(),
            );
        }

        self::assertSame(
            '',
            $client->whoami(),
        );
    }

    public function testASaslContinuationPastTheElementLimitIsAnsweredAndTheSessionContinues(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--sasl'],
        );
        $queue = $this->rawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                1,
                new SaslBindRequest('CRAM-MD5'),
            ));
            self::assertSame(
                [1 => ResultCode::SASL_BIND_IN_PROGRESS],
                $this->resultCodesFor(
                    $queue,
                    1,
                ),
            );

            $queue->sendMessage(new LdapMessageRequest(
                2,
                new SaslBindRequest(
                    'CRAM-MD5',
                    'cn=user,dc=foo,dc=bar 00000000000000000000000000000000',
                ),
                ...self::controlsPastTheElementLimitWithinTheAnonymousSize(),
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
                Operations::read(''),
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

    public function testTheServerServesAgainOnceClientsPastItsOpenFileLimitLeave(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--log'],
            self::OPEN_FILE_LIMIT,
        );

        $this->closeRawClients($this->openRawClients(100));

        $this->authenticateUser();
        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testFailedAcceptsAreLoggedOnceAndTheClientWaitingOnThemIsServed(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--log',
                '--fail-accept=3',
            ],
        );

        $this->authenticateUser();

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
        self::assertSame(
            1,
            substr_count(
                $this->waitForServerOutput('Accepting incoming connections recovered.'),
                'Failed to accept incoming connection.',
            ),
        );
    }

    public function testAClientThatStopsReadingIsDisconnectedAfterOneWriteTimeoutAndOthersAreStillServed(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--log',
                '--write-timeout=' . self::STALLED_WRITE_TIMEOUT,
                '--entries=300',
                '--entry-padding=65536',
            ],
        );

        $stalled = $this->boundRawQueue();
        $startedAt = microtime(true);
        $stalled->sendMessage(new LdapMessageRequest(
            2,
            Operations::search(Filters::present('objectClass'))->base('dc=foo,dc=bar'),
        ));

        try {
            $this->waitForServerOutput('The connection was closed because the client stopped reading.');
        } finally {
            $stalled->close();
        }

        self::assertLessThan(
            2 * self::STALLED_WRITE_TIMEOUT,
            microtime(true) - $startedAt,
        );
        $this->authenticateUser();
        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function transportProvider(): array
    {
        return [
            'plain' => ['tcp'],
            'tls' => ['ssl'],
        ];
    }

    #[DataProvider('transportProvider')]
    public function testARequestThatTakesTooLongToArriveEndsTheSessionAndOthersAreStillServed(string $transport): void
    {
        $this->createServerProcess(
            $transport,
            [
                '--log',
                '--request-read-timeout=' . self::REQUEST_READ_TIMEOUT,
            ],
        );

        $closedAfter = $this->dripRequestUntilClosed(
            $transport,
            4 * self::REQUEST_READ_TIMEOUT,
        );

        self::assertNotNull($closedAfter);
        self::assertLessThan(
            2 * self::REQUEST_READ_TIMEOUT,
            $closedAfter,
        );
        $this->waitForServerOutput('The connection was closed because a request took too long to arrive.');
        $this->authenticateUser();
        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
        );
    }

    public function testAnIdleConnectionOutlivesTheRequestReadTimeout(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--request-read-timeout=1'],
        );
        $this->authenticateUser();

        usleep(1_500_000);

        self::assertSame(
            'dn:cn=user,dc=foo,dc=bar',
            $this->ldapClient()->whoami(),
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
        ?int $openFileLimit = null,
    ): void {
        parent::createServerProcess(
            $transport,
            [...$extraArgs, ...static::runnerArgs()],
            $openFileLimit,
        );
    }

    /**
     * Connects without binding, leaving each connection for the server to accept and hold.
     *
     * @return list<resource>
     */
    protected function openRawClients(int $count): array
    {
        $clients = [];
        for ($i = 0; $i < $count; $i++) {
            $client = @stream_socket_client(
                'tcp://127.0.0.1:' . TestWorker::port(),
                $errorNumber,
                $errorMessage,
                0.1,
            );
            if ($client !== false) {
                $clients[] = $client;
            }
        }

        return $clients;
    }

    /**
     * @param list<resource> $clients
     */
    protected function closeRawClients(array $clients): void
    {
        foreach ($clients as $client) {
            fclose($client);
        }
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

    private function assertAnsweredAsAnAdministrativeLimit(
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

    private function assertASearchPastTheAnonymousSizeEndsTheSession(
        ClientQueue $queue,
        int $messageId,
    ): void {
        try {
            $queue->sendMessage(new LdapMessageRequest(
                $messageId,
                self::searchPastTheAnonymousSize(),
            ));
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
    }

    private static function baseSearch(): SearchRequest
    {
        return Operations::search(Filters::present('objectClass'))
            ->base('dc=foo,dc=bar')
            ->useBaseScope();
    }

    private static function searchSelecting(int $attributes): SearchRequest
    {
        return Operations::search(
            Filters::present('objectClass'),
            ...self::attributeNames($attributes),
        )
            ->base('dc=foo,dc=bar')
            ->useBaseScope();
    }

    /**
     * @return list<string>
     */
    private static function attributeNames(int $count): array
    {
        return array_map(
            static fn(int $i): string => "attr{$i}",
            range(
                1,
                $count,
            ),
        );
    }

    /**
     * A base search a little over the 256 KiB a session without a bind may send, matching nothing.
     */
    private static function searchPastTheAnonymousSize(): SearchRequest
    {
        return Operations::search(Filters::equal(
            'cn',
            str_repeat(
                'x',
                300_000,
            ),
        ))
            ->base('dc=foo,dc=bar')
            ->useBaseScope();
    }

    /**
     * Controls past the element limit that stay within the size a session without a bind may send.
     *
     * @return list<Control>
     */
    private static function controlsPastTheElementLimitWithinTheAnonymousSize(): array
    {
        return array_fill(
            0,
            55_000,
            new Control(''),
        );
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
