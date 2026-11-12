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

namespace Tests\Unit\FreeDSx\Ldap\Protocol;

use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\DisconnectSender;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class DisconnectSenderTest extends TestCase
{
    private ServerQueue&MockObject $queue;

    private RecordingLogger $logger;

    private DisconnectSender $subject;

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sent = [];

    protected function setUp(): void
    {
        $this->queue = $this->createMock(ServerQueue::class);
        $this->logger = new RecordingLogger();
        $this->sent = [];

        $this->queue
            ->method('sendMessage')
            ->willReturnCallback(function (LdapMessageResponse ...$messages): ServerQueue {
                foreach ($messages as $message) {
                    $this->sent[] = $message;
                }

                return $this->queue;
            });

        $this->subject = new DisconnectSender(
            $this->queue,
            new EventLogger(
                $this->logger,
                EventLogPolicy::all(),
            ),
        );
    }

    public function test_a_notice_of_disconnection_is_sent_and_recorded(): void
    {
        $this->subject->send(
            'The server is shutting down.',
            ResultCode::UNAVAILABLE,
        );

        self::assertCount(
            1,
            $this->sent,
        );
        $response = $this->sent[0]->getResponse();
        self::assertInstanceOf(
            ExtendedResponse::class,
            $response,
        );
        self::assertSame(
            ExtendedResponse::OID_NOTICE_OF_DISCONNECTION,
            $response->getName(),
        );
        self::assertSame(
            [ServerEvent::NoticeOfDisconnectSent->value],
            $this->logger->events(),
        );
    }

    public function test_no_notice_is_sent_or_recorded_once_a_write_failed(): void
    {
        $this->queue
            ->method('hasFailedWrite')
            ->willReturn(true);

        $this->subject->send(
            'The server is shutting down.',
            ResultCode::UNAVAILABLE,
        );

        self::assertSame(
            [],
            $this->sent,
        );
        self::assertSame(
            [],
            $this->logger->events(),
        );
    }
}
