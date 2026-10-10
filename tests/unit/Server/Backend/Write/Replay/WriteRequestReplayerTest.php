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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write\Replay;

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\RecordRefusedException;
use FreeDSx\Ldap\Ldif\LdifChangeRecord;
use FreeDSx\Ldap\Operation\Response\DeleteResponse;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseStream;
use FreeDSx\Ldap\Server\Backend\Write\Replay\WriteRequestReplayer;
use FreeDSx\Ldap\Server\Middleware\Pipeline\MiddlewareHandlerInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class WriteRequestReplayerTest extends TestCase
{
    private MiddlewareHandlerInterface&MockObject $pipeline;

    private WriteRequestReplayer $subject;

    protected function setUp(): void
    {
        $this->pipeline = $this->createMock(MiddlewareHandlerInterface::class);

        $this->subject = new WriteRequestReplayer($this->pipeline);
    }

    public function test_a_refusal_answered_as_a_response_keeps_the_servers_diagnostic(): void
    {
        $this->pipeline
            ->method('handle')
            ->willReturn(ResponseStream::of(
                [new LdapMessageResponse(
                    1,
                    new DeleteResponse(
                        ResultCode::UNWILLING_TO_PERFORM,
                        '',
                        'The replica is read-only.',
                    ),
                )],
                OperationOutcomeResult::failed(ResultCode::UNWILLING_TO_PERFORM),
            ));

        try {
            $this->subject->apply([new LdifChangeRecord(
                Operations::delete('cn=foo,dc=x'),
                line: 3,
            )]);
            self::fail('The refused record should have been raised.');
        } catch (RecordRefusedException $e) {
            self::assertSame(
                'The replica is read-only (entry "cn=foo,dc=x", LDIF line 3).',
                $e->getMessage(),
            );
            self::assertSame(
                ResultCode::UNWILLING_TO_PERFORM,
                $e->getCode(),
            );
        }
    }

    public function test_a_thrown_refusal_is_wrapped_with_its_record_and_kept_as_the_cause(): void
    {
        $refusal = new OperationException(
            'No such object.',
            ResultCode::NO_SUCH_OBJECT,
        );
        $this->pipeline
            ->method('handle')
            ->willThrowException($refusal);

        try {
            $this->subject->apply([new LdifChangeRecord(
                Operations::delete('cn=foo,dc=x'),
                line: 7,
            )]);
            self::fail('The refused record should have been raised.');
        } catch (RecordRefusedException $e) {
            self::assertSame(
                'cn=foo,dc=x',
                $e->getDn()->toString(),
            );
            self::assertSame(
                7,
                $e->getLdifLine(),
            );
            self::assertSame(
                ResultCode::NO_SUCH_OBJECT,
                $e->getCode(),
            );
            self::assertSame(
                $refusal,
                $e->getPrevious(),
            );
        }
    }
}
