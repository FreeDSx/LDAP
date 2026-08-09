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

namespace Tests\Unit\FreeDSx\Ldap\Server\Middleware;

use FreeDSx\Ldap\Exception\RequestValidationException;
use FreeDSx\Ldap\Operation\Request\ExtendedRequest;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Middleware\RequestValidationMiddleware;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Middleware\CallbackMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\CallLog;
use Tests\Support\FreeDSx\Ldap\Middleware\RecordingMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddlewareHandler;

final class RequestValidationMiddlewareTest extends TestCase
{
    private RequestValidationMiddleware $subject;

    private CallLog $log;

    private RecordingMiddlewareHandler $next;

    protected function setUp(): void
    {
        $this->subject = new RequestValidationMiddleware();
        $this->log = new CallLog();
        $this->next = new RecordingMiddlewareHandler($this->log);
    }

    public function test_a_message_id_of_zero_is_rejected(): void
    {
        $this->expectException(RequestValidationException::class);
        $this->expectExceptionMessage('The message ID 0 cannot be used in a client request.');

        $this->subject->process(
            $this->contextFor(0),
            $this->next,
        );
    }

    public function test_a_message_id_still_being_served_is_rejected(): void
    {
        $reuseWhileInFlight = new CallbackMiddlewareHandler(function (): OperationResult {
            $this->subject->process(
                $this->contextFor(1),
                $this->next,
            );

            return OperationOutcomeResult::succeeded();
        });

        $this->expectException(RequestValidationException::class);
        $this->expectExceptionMessage('The message ID 1 is not valid.');

        $this->subject->process(
            $this->contextFor(1),
            $reuseWhileInFlight,
        );
    }

    public function test_a_message_id_is_reusable_once_its_operation_completes(): void
    {
        $this->subject->process(
            $this->contextFor(1),
            $this->next,
        );
        $this->subject->process(
            $this->contextFor(1),
            $this->next,
        );

        self::assertSame(
            ['terminal', 'terminal'],
            $this->log->entries,
        );
    }

    public function test_an_id_is_released_when_the_operation_fails(): void
    {
        try {
            $this->subject->process(
                $this->contextFor(1),
                new ThrowingMiddlewareHandler(new RuntimeException('Operation failed.')),
            );
        } catch (RuntimeException) {
        }

        $this->subject->process(
            $this->contextFor(1),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    public function test_a_valid_message_id_is_delegated(): void
    {
        $this->subject->process(
            $this->contextFor(1),
            $this->next,
        );

        self::assertNotNull($this->next->received);
    }

    private function contextFor(int $messageId): ServerRequestContext
    {
        return new ServerRequestContext(new LdapMessageRequest(
            $messageId,
            new ExtendedRequest(ExtendedRequest::OID_WHOAMI),
        ));
    }
}
