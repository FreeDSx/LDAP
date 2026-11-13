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

use FreeDSx\Ldap\Entry\Change;
use FreeDSx\Ldap\Exception\UnsolicitedNotificationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\Queue\ClientQueue;
use FreeDSx\Ldap\Search\Filters;
use Tests\Support\FreeDSx\Ldap\Protocol\NestedSequenceRequest;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;

use function array_fill;
use function str_repeat;

trait SessionEndingLimitTestsTrait
{
    use RawClientQueueTrait;

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
}
