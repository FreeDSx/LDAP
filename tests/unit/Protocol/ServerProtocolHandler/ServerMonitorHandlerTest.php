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

namespace Tests\Unit\FreeDSx\Ldap\Protocol\ServerProtocolHandler;

use FreeDSx\Ldap\Server\ServerRunner\RunnerMode;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Operation\OperationType;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerMonitorHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Metrics\Observation\ConnectionObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\OperationObservation;
use FreeDSx\Ldap\Server\Metrics\Observation\TrafficObservation;
use FreeDSx\Ldap\Server\Metrics\Recorder\InMemoryMetricsRecorder;
use FreeDSx\Ldap\Server\ServerRunner\PcntlServerRunner;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use FreeDSx\Ldap\ServerOptions;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerMonitorHandlerTest extends TestCase
{
    private TokenInterface&MockObject $mockToken;

    private InMemoryMetricsRecorder $metrics;

    private ServerMonitorHandler $subject;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->metrics = new InMemoryMetricsRecorder();

        $this->subject = new ServerMonitorHandler(
            options: new ServerOptions(),
            snapshots: $this->metrics,
        );
    }

    public function test_it_serves_the_cn_monitor_entry(): void
    {
        $stream = $this->subject->handleRequest(
            $this->makeMessage(),
            $this->mockToken,
        );
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();
        $entry = $result->getEntry();

        self::assertSame(
            'cn=monitor',
            $entry->getDn()->toString(),
        );
        self::assertTrue($entry->get('objectClass')?->has('extensibleObject') ?? false);
        self::assertEquals(
            new LdapMessageResponse(
                1,
                new SearchResultDone(ResultCode::SUCCESS),
            ),
            $messages[1],
        );
    }

    public function test_it_reports_the_live_connection_gauges(): void
    {
        $this->metrics->connectionObserved(ConnectionObservation::Opened);
        $this->metrics->connectionObserved(ConnectionObservation::Opened);
        $this->metrics->connectionObserved(ConnectionObservation::Closed);

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['1'],
            $entry->get('connectionsActive')?->getValues(),
        );
        self::assertSame(
            ['2'],
            $entry->get('connectionsTotal')?->getValues(),
        );
    }

    public function test_it_reports_operation_totals_and_a_per_type_breakdown(): void
    {
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            false,
            0.1,
            ResultCode::NO_SUCH_OBJECT,
        ));

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['2'],
            $entry->get('operationsCompleted')?->getValues(),
        );
        self::assertSame(
            ['1'],
            $entry->get('operationsFailed')?->getValues(),
        );
        self::assertSame(
            ['search=2'],
            $entry->get('operationsByType')?->getValues(),
        );
    }

    public function test_it_reports_a_result_code_breakdown(): void
    {
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Add,
            false,
            0.1,
            ResultCode::NO_SUCH_OBJECT,
        ));

        $entry = $this->handleAndCaptureEntry();

        self::assertEqualsCanonicalizing(
            [
                ResultCode::SUCCESS . '=1',
                ResultCode::NO_SUCH_OBJECT . '=1',
            ],
            $entry->get('operationsByResultCode')?->getValues(),
        );
    }

    public function test_it_reports_bind_method_and_search_scope_breakdowns(): void
    {
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Bind,
            true,
            0.1,
            ResultCode::SUCCESS,
            bindMethod: 'anonymous',
        ));
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
            searchScope: 'sub',
        ));

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['anonymous=1'],
            $entry->get('bindsByMethod')?->getValues(),
        );
        self::assertSame(
            ['sub=1'],
            $entry->get('searchesByScope')?->getValues(),
        );
    }

    public function test_it_reports_the_average_latency_per_type_in_milliseconds(): void
    {
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.1,
            ResultCode::SUCCESS,
        ));
        $this->metrics->operationObserved(new OperationObservation(
            OperationType::Search,
            true,
            0.3,
            ResultCode::SUCCESS,
        ));

        $entry = $this->handleAndCaptureEntry();

        // (0.1 + 0.3) / 2 = 0.2s = 200ms
        self::assertSame(
            ['search=200'],
            $entry->get('operationsAvgLatencyMsByType')?->getValues(),
        );
    }

    public function test_it_reports_the_server_host(): void
    {
        $host = gethostname();

        if ($host === false) {
            self::markTestSkipped('gethostname() is unavailable on this system.');
        }

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            [$host],
            $entry->get('serverHost')?->getValues(),
        );
    }

    public function test_it_reports_the_runner_class(): void
    {
        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            [PcntlServerRunner::class],
            $entry->get('serverRunner')?->getValues(),
        );
    }

    public function test_it_omits_the_start_time_when_unknown(): void
    {
        $entry = $this->handleAndCaptureEntry();

        self::assertNull($entry->get('serverStartTime'));
        self::assertNull($entry->get('serverUptimeSeconds'));
    }

    public function test_it_reports_connections_closed_by_an_oversized_request(): void
    {
        $this->metrics->connectionObserved(ConnectionObservation::RequestSizeExceeded);
        $this->metrics->connectionObserved(ConnectionObservation::RequestSizeExceeded);

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['2'],
            $entry->get('connectionsRequestSizeExceeded')?->getValues(),
        );
    }

    public function test_it_reports_connections_closed_by_a_protocol_error(): void
    {
        $this->metrics->connectionObserved(ConnectionObservation::ProtocolError);
        $this->metrics->connectionObserved(ConnectionObservation::ProtocolError);

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['2'],
            $entry->get('connectionsProtocolErrors')?->getValues(),
        );
    }

    public function test_it_reports_traffic_totals(): void
    {
        $this->metrics->trafficObserved(new TrafficObservation(
            bytesSent: 2048,
            bytesReceived: 256,
            entriesReturned: 7,
        ));

        $entry = $this->handleAndCaptureEntry();

        self::assertSame(
            ['2048'],
            $entry->get('trafficBytesSent')?->getValues(),
        );
        self::assertSame(
            ['256'],
            $entry->get('trafficBytesReceived')?->getValues(),
        );
        self::assertSame(
            ['7'],
            $entry->get('trafficEntriesReturned')?->getValues(),
        );
    }

    public function test_it_omits_in_flight_operations_under_the_forking_runner(): void
    {
        $this->metrics->operationStarted(OperationType::Search);

        $entry = $this->handleAndCaptureEntry();

        self::assertNull($entry->get('operationsInProgressByType'));
    }

    public function test_it_reports_in_flight_operations_under_a_coroutine_runner(): void
    {
        $this->metrics->operationStarted(OperationType::Search);

        $subject = new ServerMonitorHandler(
            options: (new ServerOptions())->setRunner(RunnerMode::Swoole),
            snapshots: $this->metrics,
        );

        $entry = $this->handleAndCaptureEntry($subject);

        self::assertSame(
            ['search=1'],
            $entry->get('operationsInProgressByType')?->getValues(),
        );
    }

    private function makeMessage(): LdapMessageRequest
    {
        return new LdapMessageRequest(
            1,
            (new SearchRequest(Filters::present('objectClass')))
                ->base('cn=monitor')
                ->useBaseScope(),
        );
    }

    private function handleAndCaptureEntry(?ServerMonitorHandler $subject = null): Entry
    {
        $stream = ($subject ?? $this->subject)->handleRequest(
            $this->makeMessage(),
            $this->mockToken,
        );
        $messages = [...$stream->messages];

        /** @var SearchResultEntry $result */
        $result = $messages[0]->getResponse();

        return $result->getEntry();
    }
}
