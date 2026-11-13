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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filters;
use PHPUnit\Framework\Attributes\DataProvider;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;
use Tests\Support\FreeDSx\Ldap\RequestBudgetClientTrait;

use function array_map;
use function fclose;
use function fwrite;
use function microtime;
use function range;
use function str_repeat;
use function substr;
use function usleep;

/**
 * Connections served by one process share its request budget.
 */
trait SharedRequestBudgetTestsTrait
{
    use RawClientQueueTrait;
    use RequestBudgetClientTrait;

    public function testARequestIsAnsweredBusyWhileOtherConnectionsHoldWhatTheProcessMayHold(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--max-held-request-size=200000'],
        );
        $stalled = $this->stalledClient(120_000);
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                self::searchHoldingManyElements(),
            ));
            $queue->sendMessage(new LdapMessageRequest(
                3,
                Operations::read('dc=foo,dc=bar'),
            ));
            self::assertSame(
                [
                    2 => ResultCode::BUSY,
                    3 => ResultCode::SUCCESS,
                ],
                $this->resultCodesFor(
                    $queue,
                    2,
                    3,
                ),
            );

            fclose($stalled);

            self::assertSame(
                ResultCode::SUCCESS,
                $this->resultOnceTheBudgetIsReleased($queue),
            );
        } finally {
            $queue->close();
        }
    }

    /**
     * @return iterable<string, array{RequestInterface}>
     */
    public static function noResponseProvider(): iterable
    {
        yield 'abandon' => [Operations::abandon(1)];
        yield 'unbind' => [new UnbindRequest()];
    }

    #[DataProvider('noResponseProvider')]
    public function testARefusedRequestWithNoResponseIsDroppedAndTheSessionContinues(RequestInterface $request): void
    {
        $this->createServerProcess(
            'tcp',
            ['--max-held-request-size=200000'],
        );
        $stalled = $this->stalledClient(150_000);
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                $request,
                ...array_map(
                    static fn(int $i): Control => new Control(
                        '1.3.6.1.4.1.99999.' . $i,
                        false,
                        'value',
                    ),
                    range(
                        1,
                        60,
                    ),
                ),
            ));
            $queue->sendMessage(new LdapMessageRequest(
                3,
                Operations::read('dc=foo,dc=bar'),
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
            fclose($stalled);
        }
    }

    public function testReadingARequestWaitsUntilOtherConnectionsReleaseWhatTheProcessMayHold(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--max-held-request-size=200000',
                '--request-read-timeout=3',
            ],
        );
        $stalled = $this->stalledClient(120_000);
        $queue = $this->boundRawQueue();

        try {
            $startedAt = microtime(true);
            $queue->sendMessage(new LdapMessageRequest(
                2,
                Operations::search(Filters::equal(
                    'cn',
                    str_repeat(
                        'x',
                        100_000,
                    ),
                ))->base('dc=foo,dc=bar'),
            ));
            $resultCodes = $this->resultCodesFor(
                $queue,
                2,
            );
            $waited = microtime(true) - $startedAt;
        } finally {
            $queue->close();
            fclose($stalled);
        }

        self::assertSame(
            [2 => ResultCode::SUCCESS],
            $resultCodes,
        );
        self::assertGreaterThan(
            1.0,
            $waited,
        );
    }

    public function testRequestsArrivingTogetherPastWhatTheProcessMayHoldAreEachAnswered(): void
    {
        $this->createServerProcess(
            'tcp',
            [
                '--max-held-request-size=100000',
                '--request-read-timeout=5',
            ],
        );
        $requests = self::encodedRequest(new LdapMessageRequest(
            1,
            Operations::bind(
                'cn=user,dc=foo,dc=bar',
                '12345',
            ),
        )) . self::encodedRequest(new LdapMessageRequest(
            2,
            Operations::search(Filters::equal(
                'cn',
                str_repeat(
                    'x',
                    60_000,
                ),
            ))->base('dc=foo,dc=bar'),
        ));
        $clients = [
            $this->openClient(),
            $this->openClient(),
            $this->openClient(),
        ];

        try {
            foreach ($clients as $client) {
                fwrite(
                    $client,
                    substr(
                        $requests,
                        0,
                        30_000,
                    ),
                );
            }
            // Gives the server time to start reading every search before any of them can finish.
            usleep(500_000);
            foreach ($clients as $client) {
                fwrite(
                    $client,
                    substr(
                        $requests,
                        30_000,
                    ),
                );
            }

            self::assertSame(
                [ResultCode::SUCCESS, ResultCode::SUCCESS, ResultCode::SUCCESS],
                array_map(
                    fn($client): ?int => $this->resultCodeFor(
                        $client,
                        2,
                    ),
                    $clients,
                ),
            );
        } finally {
            foreach ($clients as $client) {
                fclose($client);
            }
        }
    }

    /**
     * Retries until the server notices the stalled connection closed and stops answering busy.
     */
    private function resultOnceTheBudgetIsReleased(ClientQueue $queue): ?int
    {
        $resultCode = null;
        for ($messageId = 4; $messageId < 24; $messageId++) {
            $queue->sendMessage(new LdapMessageRequest(
                $messageId,
                self::searchHoldingManyElements(),
            ));
            $resultCode = $this->resultCodesFor(
                $queue,
                $messageId,
            )[$messageId] ?? null;
            if ($resultCode !== ResultCode::BUSY) {
                return $resultCode;
            }
            usleep(100_000);
        }

        return $resultCode;
    }
}
