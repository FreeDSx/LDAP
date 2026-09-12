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

use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\AnonBindRequest;
use FreeDSx\Ldap\Operation\Request\RequestInterface;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Request\SimpleBindRequest;
use FreeDSx\Ldap\Operation\Request\UnbindRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\Metrics\Rollup\OperationRollupCoordinator;
use FreeDSx\Ldap\Server\Middleware\MetricsMiddleware;
use FreeDSx\Ldap\Server\Middleware\Pipeline\ServerRequestContext;
use FreeDSx\Ldap\Server\Operation\OperationOutcomeResult;
use PHPUnit\Framework\TestCase;
use RuntimeException;
use Tests\Support\FreeDSx\Ldap\Middleware\CallbackMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\StubMiddlewareHandler;
use Tests\Support\FreeDSx\Ldap\Middleware\ThrowingMiddlewareHandler;

final class MetricsMiddlewareTest extends TestCase
{
    private InMemoryMetricsRecorder $recorder;

    private MetricsMiddleware $subject;

    protected function setUp(): void
    {
        $this->recorder = new InMemoryMetricsRecorder();
        $this->subject = new MetricsMiddleware($this->recorder);
    }

    public function test_it_records_a_successful_operation(): void
    {
        $this->subject->process(
            $this->contextFor(new SearchRequest(Filters::present('objectClass'))),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        $operations = $this->recorder->snapshot()->operations;

        self::assertSame(
            ['search' => 1],
            $operations->counts,
        );
        self::assertSame(
            [],
            $operations->errors,
        );
        self::assertSame(
            [ResultCode::SUCCESS => 1],
            $operations->resultCodeCounts,
        );
    }

    public function test_an_unbind_is_counted_without_inventing_a_result_code_for_it(): void
    {
        $this->subject->process(
            $this->contextFor(new UnbindRequest()),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        $operations = $this->recorder->snapshot()->operations;

        self::assertSame(
            ['unbind' => 1],
            $operations->counts,
        );
        self::assertSame(
            [],
            $operations->resultCodeCounts,
        );
    }

    public function test_an_abandon_is_counted_without_inventing_a_result_code_for_it(): void
    {
        $this->subject->process(
            $this->contextFor(new AbandonRequest(1)),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        self::assertSame(
            [],
            $this->recorder->snapshot()->operations->resultCodeCounts,
        );
    }

    public function test_it_records_a_returned_failure_with_its_result_code(): void
    {
        $this->subject->process(
            $this->contextFor(new SearchRequest(Filters::present('objectClass'))),
            new StubMiddlewareHandler(OperationOutcomeResult::failed(ResultCode::NO_SUCH_OBJECT)),
        );

        $operations = $this->recorder->snapshot()->operations;

        self::assertSame(
            ['search' => 1],
            $operations->errors,
        );
        self::assertSame(
            [ResultCode::NO_SUCH_OBJECT => 1],
            $operations->resultCodeCounts,
        );
    }

    public function test_a_thrown_operation_exception_is_recorded_and_rethrown(): void
    {
        $caught = null;

        try {
            $this->subject->process(
                $this->contextFor(new SimpleBindRequest('cn=user,dc=foo,dc=bar', 'secret')),
                new ThrowingMiddlewareHandler(new OperationException(
                    'Denied.',
                    ResultCode::INSUFFICIENT_ACCESS_RIGHTS,
                )),
            );
        } catch (OperationException $e) {
            $caught = $e;
        }

        self::assertInstanceOf(
            OperationException::class,
            $caught,
        );

        $operations = $this->recorder->snapshot()->operations;

        self::assertSame(
            ['bind' => 1],
            $operations->errors,
        );
        self::assertSame(
            [ResultCode::INSUFFICIENT_ACCESS_RIGHTS => 1],
            $operations->resultCodeCounts,
        );
    }

    public function test_it_raises_the_in_flight_gauge_during_handling_and_clears_it_after(): void
    {
        $inFlightDuring = [];

        $this->subject->process(
            $this->contextFor(new SearchRequest(Filters::present('objectClass'))),
            new CallbackMiddlewareHandler(function () use (&$inFlightDuring) {
                $inFlightDuring = $this->recorder->snapshot()->operationsInProgress;

                return OperationOutcomeResult::succeeded();
            }),
        );

        self::assertSame(
            ['search' => 1],
            $inFlightDuring,
        );
        self::assertSame(
            [],
            $this->recorder->snapshot()->operationsInProgress,
        );
    }

    public function test_an_unexpected_throwable_is_recorded_and_clears_the_in_flight_gauge(): void
    {
        $caught = null;

        try {
            $this->subject->process(
                $this->contextFor(new SearchRequest(Filters::present('objectClass'))),
                new ThrowingMiddlewareHandler(new RuntimeException('boom')),
            );
        } catch (RuntimeException $e) {
            $caught = $e;
        }

        self::assertInstanceOf(
            RuntimeException::class,
            $caught,
        );

        $operations = $this->recorder->snapshot()->operations;

        self::assertSame(
            ['search' => 1],
            $operations->errors,
        );
        self::assertSame(
            [ResultCode::OPERATIONS_ERROR => 1],
            $operations->resultCodeCounts,
        );
        self::assertSame(
            [],
            $this->recorder->snapshot()->operationsInProgress,
        );
    }

    public function test_it_records_the_bind_method_dimension(): void
    {
        $this->subject->process(
            $this->contextFor(new AnonBindRequest()),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );
        $this->subject->process(
            $this->contextFor(new SimpleBindRequest('cn=user,dc=foo,dc=bar', 'secret')),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        self::assertSame(
            ['anonymous' => 1, 'simple' => 1],
            $this->recorder->snapshot()->operations->bindCounts,
        );
    }

    public function test_it_records_the_search_scope_dimension(): void
    {
        $this->subject->process(
            $this->contextFor((new SearchRequest(Filters::present('objectClass')))->useBaseScope()),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );

        self::assertSame(
            ['base' => 1],
            $this->recorder->snapshot()->operations->searchScopeCounts,
        );
    }

    public function test_it_streams_each_recorded_operation_to_the_rollup_coordinator(): void
    {
        if (str_starts_with(strtoupper(PHP_OS), 'WIN')) {
            self::markTestSkipped('The rollup uses a UNIX socket pair, unavailable on Windows; it is Linux/PCNTL-only.');
        }

        $coordinator = new OperationRollupCoordinator($this->recorder);
        $channel = $coordinator->openChannel();
        $coordinator->enterChild($channel);
        $subject = new MetricsMiddleware(
            $this->recorder,
            $coordinator,
        );

        $subject->process(
            $this->contextFor(new SearchRequest(Filters::present('objectClass'))),
            new StubMiddlewareHandler(OperationOutcomeResult::succeeded()),
        );
        // The coordinator batches sends. force it done for the test.
        $coordinator->finish();

        $parentRecorder = new InMemoryMetricsRecorder();
        (new OperationRollupCoordinator($parentRecorder))->collect($channel);

        self::assertSame(
            ['search' => 1],
            $parentRecorder->snapshot()->operations->counts,
        );
    }

    private function contextFor(RequestInterface $request): ServerRequestContext
    {
        return new ServerRequestContext(new LdapMessageRequest(
            1,
            $request,
        ));
    }
}
