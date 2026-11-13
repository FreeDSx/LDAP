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

namespace Tests\Integration\FreeDSx\Ldap\Runner\Concern;

use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FreeDSx\Ldap\DripsRequestsTrait;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function microtime;
use function substr_count;

trait ConnectionTestsTrait
{
    use RawClientQueueTrait;
    use DripsRequestsTrait;

    /**
     * Seconds a write may stall in the stalled-reader test.
     */
    private const STALLED_WRITE_TIMEOUT = 3;

    /**
     * Seconds a request may take to arrive in the dripped-request test.
     */
    private const REQUEST_READ_TIMEOUT = 2;

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
}
