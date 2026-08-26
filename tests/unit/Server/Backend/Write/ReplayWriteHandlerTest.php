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

namespace Tests\Unit\FreeDSx\Ldap\Server\Backend\Write;

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Backend\Write\ReplayWriteHandler;
use FreeDSx\Ldap\Server\Backend\Write\WriteContext;
use FreeDSx\Ldap\Server\Backend\Write\WriteHandlerInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestInterface;
use FreeDSx\Ldap\Server\Backend\Write\WriteRequestRouter;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Token\SystemToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ReplayWriteHandlerTest extends TestCase
{
    private const DN = 'cn=foo,dc=example,dc=com';

    private WriteHandlerInterface&MockObject $writeHandler;

    private ReplayWriteHandler $subject;

    protected function setUp(): void
    {
        $this->writeHandler = $this->createMock(WriteHandlerInterface::class);

        $this->subject = new ReplayWriteHandler(new WriteRequestRouter($this->writeHandler));
    }

    public function test_it_applies_the_write_and_reports_success(): void
    {
        $this->writeHandler
            ->expects(self::once())
            ->method('handle');

        self::assertSame(
            OperationOutcome::Succeeded,
            $this->subject->handle($this->contextWith())
                ->outcome()
                ->outcome(),
        );
    }

    public function test_the_controls_reach_the_write_context(): void
    {
        $seen = null;
        $this->writeHandler
            ->method('handle')
            ->willReturnCallback(static function (
                WriteRequestInterface $request,
                WriteContext $context,
            ) use (&$seen): void {
                $seen = $context->getControls();
            });

        $this->subject->handle($this->contextWith(new Control(Control::OID_RELAX_RULES)));

        self::assertTrue($seen?->has(Control::OID_RELAX_RULES));
    }

    public function test_a_critical_control_it_cannot_honor_is_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION);

        $this->subject->handle($this->contextWith(new Control(
            Control::OID_PRE_READ,
            criticality: true,
        )));
    }

    public function test_a_non_critical_control_it_cannot_honor_is_ignored(): void
    {
        $this->writeHandler
            ->expects(self::once())
            ->method('handle');

        $this->subject->handle($this->contextWith(new Control(Control::OID_PRE_READ)));
    }

    public function test_a_critical_control_it_can_honor_is_applied(): void
    {
        $this->writeHandler
            ->expects(self::once())
            ->method('handle');

        $this->subject->handle($this->contextWith(new Control(
            Control::OID_RELAX_RULES,
            criticality: true,
        )));
    }

    public function test_a_critical_password_policy_control_is_refused(): void
    {
        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::UNAVAILABLE_CRITICAL_EXTENSION);

        $this->subject->handle($this->contextWith(new Control(
            Control::OID_PWD_POLICY,
            criticality: true,
        )));
    }

    private function contextWith(Control ...$controls): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(
                1,
                new AddRequest(Entry::create(self::DN)),
                ...$controls,
            ),
            new SystemToken(),
        );
    }
}
