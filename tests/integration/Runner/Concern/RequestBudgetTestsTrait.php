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
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use Tests\Support\FreeDSx\Ldap\RawClientQueueTrait;
use Tests\Support\FreeDSx\Ldap\RequestBudgetClientTrait;

use function str_repeat;

trait RequestBudgetTestsTrait
{
    use RawClientQueueTrait;
    use RequestBudgetClientTrait;

    public function testARequestTooLargeToHoldIsAnsweredAsAnAdministrativeLimitAndTheSessionContinues(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--max-held-request-size=80000'],
        );
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
                    2 => ResultCode::ADMIN_LIMIT_EXCEEDED,
                    3 => ResultCode::SUCCESS,
                ],
                $this->resultCodesFor(
                    $queue,
                    2,
                    3,
                ),
            );
        } finally {
            $queue->close();
        }
    }

    public function testARequestDeclaringMoreThanTheProcessCouldEverHoldEndsTheSessionAtOnce(): void
    {
        $this->createServerProcess(
            'tcp',
            ['--max-held-request-size=50000'],
        );
        $queue = $this->boundRawQueue();

        try {
            $queue->sendMessage(new LdapMessageRequest(
                2,
                Operations::search(Filters::equal(
                    'cn',
                    str_repeat(
                        'x',
                        60_000,
                    ),
                ))->base('dc=foo,dc=bar'),
            ));
            $queue->getMessage();
            self::fail('The connection ended without a notice of disconnection.');
        } catch (UnsolicitedNotificationException $e) {
            self::assertSame(
                [true, ResultCode::PROTOCOL_ERROR],
                [$e->isNoticeOfDisconnection(), $e->getCode()],
            );
        } finally {
            $queue->close();
        }
    }
}
