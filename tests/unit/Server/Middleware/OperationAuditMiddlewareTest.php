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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Exception\SchemaRuleException;
use FreeDSx\Ldap\Operation\Request\AddRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolationDisposition;
use FreeDSx\Ldap\Server\Backend\Write\Schema\SchemaViolations;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\OperationAuditor;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Middleware\OperationAuditMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\FailedOperationResult;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use FreeDSx\Ldap\Server\Operation\WriteOperationResult;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;
use Tests\Support\FreeDSx\Ldap\Middleware\StubMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddlewareHandler;

final class OperationAuditMiddlewareTest extends TestCase
{
    private RecordingLogger $logger;

    private OperationAuditMiddleware $subject;

    private ServerRequestContext $context;

    protected function setUp(): void
    {
        $this->logger = new RecordingLogger();
        $this->subject = new OperationAuditMiddleware(new OperationAuditor(new EventLogger(
            $this->logger,
            EventLogPolicy::all(),
        )));
        $this->context = new ServerRequestContext(
            new LdapMessageRequest(1, new AddRequest(Entry::create('cn=foo,dc=bar'))),
            BindToken::fromDn(
                'cn=alice,dc=bar',
            ),
        );
    }

    public function test_it_records_an_auditable_result(): void
    {
        $this->subject->process(
            $this->context,
            new StubMiddlewareHandler(WriteOperationResult::success(
                $this->context->message,
                new SchemaViolations(),
            )),
        );

        self::assertSame(
            ServerEvent::EntryAdded->value,
            $this->logger->records[0]['context']['event'],
        );
    }

    public function test_it_does_not_record_a_non_auditable_result(): void
    {
        $this->subject->process(
            $this->context,
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        self::assertSame(
            [],
            $this->logger->records,
        );
    }

    public function test_it_returns_the_stream_from_the_next_handler_unchanged(): void
    {
        $result = OperationOutcomeResult::failed();

        self::assertSame(
            $result,
            $this->subject->process(
                $this->context,
                new StubMiddlewareHandler($result),
            )->outcome(),
        );
    }

    public function test_it_audits_a_write_authorization_denial(): void
    {
        $this->auditFailure(
            $this->context,
            new OperationException(
                'Denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ),
        );

        self::assertTrue($this->wasLogged(ServerEvent::AuthorizationDeniedWrite));
    }

    public function test_it_audits_a_search_authorization_denial(): void
    {
        $context = $this->contextFor((new SearchRequest(Filters::present('cn')))->base('dc=bar'));

        $this->auditFailure(
            $context,
            new OperationException(
                'Denied.',
                ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
            ),
        );

        self::assertTrue($this->wasLogged(ServerEvent::AuthorizationDeniedRead));
    }

    public function test_it_audits_a_critical_control_rejection(): void
    {
        $this->auditFailure(
            $this->context,
            new OperationException(
                'Critical control 1.2.3.4 is not supported.',
                ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            ),
        );

        self::assertTrue($this->wasLogged(ServerEvent::CriticalControlRejected));
    }

    public function test_it_records_schema_violations_from_a_schema_rule_exception(): void
    {
        $violations = new SchemaViolations();
        $violations->record(
            new OperationException(
                'objectClass violation.',
                ResultCode::OBJECT_CLASS_VIOLATION,
            ),
            SchemaViolationDisposition::Rejected,
        );
        $exception = new SchemaRuleException(
            new OperationException(
                'objectClass violation.',
                ResultCode::OBJECT_CLASS_VIOLATION,
            ),
            $violations,
        );

        $this->auditFailure($this->context, $exception);

        self::assertTrue($this->wasLogged(ServerEvent::SchemaViolation));
    }

    public function test_it_lets_an_exception_from_the_next_handler_propagate(): void
    {
        $exception = new OperationException('Boom.');

        $this->expectExceptionObject($exception);

        $this->subject->process(
            $this->context,
            new ThrowingMiddlewareHandler($exception),
        );
    }

    /**
     * A failure reaches the audit middleware as a resolved FailedOperationResult, not a thrown exception.
     */
    private function auditFailure(
        ServerRequestContext $context,
        OperationException $exception,
    ): void {
        $this->subject->process(
            $context,
            new StubMiddlewareHandler(new FailedOperationResult(
                $context->message,
                $exception,
            )),
        );
    }

    private function wasLogged(ServerEvent $event): bool
    {
        foreach ($this->logger->records as $record) {
            if (($record['context']['event'] ?? null) === $event->value) {
                return true;
            }
        }

        return false;
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(
            new LdapMessageRequest(1, $request),
            BindToken::fromDn(
                'cn=alice,dc=bar',
            ),
        );
    }
}
