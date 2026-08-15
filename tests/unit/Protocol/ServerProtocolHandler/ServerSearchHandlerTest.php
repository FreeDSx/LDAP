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

use FreeDSx\Ldap\Control\Control;
use FreeDSx\Ldap\Control\Sorting\SortKey;
use FreeDSx\Ldap\Control\Sorting\SortingControl;
use FreeDSx\Ldap\Control\Sorting\SortingResponseControl;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\LdapResult;
use FreeDSx\Ldap\Operation\Request\AbandonRequest;
use FreeDSx\Ldap\Operation\Request\CancelRequest;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\ExtendedResponse;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessage;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\Response\ResponseWriter;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchHandler;
use FreeDSx\Ldap\Schema\Schema;
use FreeDSx\Ldap\Schema\SchemaResource;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\AccessControl\AccessControlInterface;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\Storage\EntryStream;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Operation\OperationOutcome;
use FreeDSx\Ldap\Server\Operation\OperationResult;
use FreeDSx\Ldap\Server\Operation\SearchOperationResult;
use FreeDSx\Ldap\Server\SearchLimits;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerSearchHandlerTest extends TestCase
{
    private ServerSearchHandler $subject;

    private ServerQueue&MockObject $mockQueue;

    private LdapBackendInterface&MockObject $mockBackend;

    private FilterEvaluatorInterface&MockObject $mockFilterEvaluator;

    private AccessControlInterface&MockObject $mockAccessControl;

    private TokenInterface&MockObject $mockToken;

    private Schema $schema;

    /**
     * @var list<LdapMessageResponse>
     */
    private array $sentMessages = [];

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockFilterEvaluator = $this->createMock(FilterEvaluatorInterface::class);
        $this->mockAccessControl = $this->createMock(AccessControlInterface::class);
        $this->schema = SchemaResource::Core->load();
        $this->sentMessages = [];

        $this->mockAccessControl
            ->method('filterEntry')
            ->willReturnArgument(1);

        $this->mockQueue
            ->method('sendMessages')
            ->willReturnCallback(function (iterable $messages): ServerQueue {
                foreach ($messages as $message) {
                    if (!$message instanceof LdapMessageResponse) {
                        continue;
                    }

                    $this->sentMessages[] = $message;
                }

                return $this->mockQueue;
            });

        $this->subject = $this->makeHandler($this->mockAccessControl);
    }

    public function test_it_should_send_entries_from_the_backend_to_the_client(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar'),
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->with(self::isInstanceOf(SearchRequest::class))
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $result = $this->drive(
            $this->subject,
            $search,
        );

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry1)),
            new LdapMessageResponse(2, new SearchResultEntry($entry2)),
            new LdapMessageResponse(
                2,
                new SearchResultDone(0),
            ),
        ]);
        self::assertInstanceOf(SearchOperationResult::class, $result);
        self::assertSame(
            OperationOutcome::Succeeded,
            $result->outcome(),
        );
    }

    #[DataProvider('outOfRangeParameterProvider')]
    public function test_it_rejects_a_search_parameter_outside_its_permitted_range(
        SearchRequest $request,
        string $expectedMessage,
    ): void {
        $this->mockBackend
            ->expects(self::never())
            ->method('search');

        self::expectExceptionObject(new OperationException(
            $expectedMessage,
            ResultCode::PROTOCOL_ERROR,
        ));

        $this->subject->handleRequest(
            new LdapMessageRequest(
                2,
                $request,
            ),
            $this->mockToken,
        );
    }

    public static function outOfRangeParameterProvider(): Generator
    {
        yield 'a scope above the enumeration' => [
            self::searchRequest()->setScope(3),
            'The search scope requested is not supported.',
        ];
        yield 'a negative scope' => [
            self::searchRequest()->setScope(-1),
            'The search scope requested is not supported.',
        ];
        yield 'an alias value above the enumeration' => [
            self::searchRequest()->setDereferenceAliases(4),
            'The alias dereferencing value requested is not valid.',
        ];
        yield 'a negative alias value' => [
            self::searchRequest()->setDereferenceAliases(-1),
            'The alias dereferencing value requested is not valid.',
        ];
        yield 'a negative size limit' => [
            self::searchRequest()->setSizeLimit(-1),
            'The size limit requested is outside the permitted range.',
        ];
        yield 'a size limit above maxInt' => [
            self::searchRequest()->setSizeLimit(LdapMessage::MAX_INT + 1),
            'The size limit requested is outside the permitted range.',
        ];
        yield 'a negative time limit' => [
            self::searchRequest()->setTimeLimit(-1),
            'The time limit requested is outside the permitted range.',
        ];
        yield 'a time limit above maxInt' => [
            self::searchRequest()->setTimeLimit(LdapMessage::MAX_INT + 1),
            'The time limit requested is outside the permitted range.',
        ];
    }

    /**
     * Scope 3 is the subordinate scope the extensible enumeration anticipates, so it is well formed but unsupported.
     */
    public function test_it_accepts_every_scope_it_supports(): void
    {
        $this->mockBackend
            ->method('search')
            ->willReturnCallback(fn(): EntryStream => new EntryStream($this->makeGenerator()));

        foreach (SearchRequest::SUPPORTED_SCOPES as $scope) {
            $result = $this->drive(
                $this->subject,
                new LdapMessageRequest(
                    2,
                    self::searchRequest()->setScope($scope),
                ),
            );

            self::assertSame(
                OperationOutcome::Succeeded,
                $result->outcome(),
            );
        }
    }

    public function test_entry_stripped_by_acl_is_excluded_when_it_no_longer_matches_filter(): void
    {
        $entry = Entry::create('dc=foo,dc=bar', ['userPassword' => 'secret', 'cn' => 'foo']);
        $stripped = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('userPassword')))->base('dc=foo,dc=bar'),
        );

        $mockAccessControl = $this->createMock(AccessControlInterface::class);
        $mockAccessControl->method('filterEntry')->willReturn($stripped);

        $subject = $this->makeHandler($mockAccessControl);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(false);

        $this->drive(
            $subject,
            $search,
        );

        $this->assertSentMessages([
            new LdapMessageResponse(
                2,
                new SearchResultDone(0),
            ),
        ]);
    }

    public function test_it_lets_an_operation_exception_from_the_backend_bubble(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal(
                'foo',
                'bar',
            )))->base('dc=foo,dc=bar'),
        );

        $this->mockBackend
            ->method('search')
            ->willThrowException(
                new OperationException(
                    "Fail",
                    ResultCode::OPERATIONS_ERROR,
                ),
            );

        $this->expectException(OperationException::class);
        $this->expectExceptionCode(ResultCode::OPERATIONS_ERROR);

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_return_size_limit_exceeded_with_partial_results_when_limit_is_hit(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))
                ->base('dc=foo,dc=bar')
                ->sizeLimit(1),
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->drive($this->subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry1)),
            new LdapMessageResponse(
                2,
                new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED),
            ),
        ]);
    }

    public function test_it_should_succeed_when_matches_equal_the_size_limit_exactly(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))
                ->base('dc=foo,dc=bar')
                ->sizeLimit(1),
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->drive($this->subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry1)),
            new LdapMessageResponse(2, new SearchResultDone(0)),
        ]);
    }

    public function test_it_should_not_enforce_size_limit_when_zero(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))
                ->base('dc=foo,dc=bar')
                ->sizeLimit(0),
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->drive($this->subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry1)),
            new LdapMessageResponse(2, new SearchResultEntry($entry2)),
            new LdapMessageResponse(2, new SearchResultDone(0)),
        ]);
    }

    public function test_server_max_search_size_applies_when_client_requests_no_limit(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))
                ->base('dc=foo,dc=bar')
                ->sizeLimit(0),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $subject = $this->makeHandler(
            $this->mockAccessControl,
            new SearchLimits(maxSearchSize: 1),
        );
        $this->drive($subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry1)),
            new LdapMessageResponse(2, new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED)),
        ]);
    }

    public function test_client_size_limit_is_used_when_below_server_max(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))
                ->base('dc=foo,dc=bar')
                ->sizeLimit(1),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $subject = $this->makeHandler(
            $this->mockAccessControl,
            new SearchLimits(maxSearchSize: 5),
        );
        $this->drive($subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry1)),
            new LdapMessageResponse(2, new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED)),
        ]);
    }

    public function test_server_max_search_size_caps_client_limit_when_exceeded(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))
                ->base('dc=foo,dc=bar')
                ->sizeLimit(5),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry1, $entry2)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $subject = $this->makeHandler(
            $this->mockAccessControl,
            new SearchLimits(maxSearchSize: 1),
        );
        $this->drive($subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry1)),
            new LdapMessageResponse(2, new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED)),
        ]);
    }

    public function test_it_should_send_a_successful_SearchResultDone_when_no_entries_match(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar'),
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $search,
        );

        $this->assertSentMessages([
            new LdapMessageResponse(
                2,
                new SearchResultDone(0),
            ),
        ]);
    }

    public function test_it_should_suppress_entry_when_filter_entry_returns_null(): void
    {
        $entry1 = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo'],
        );
        $entry2 = Entry::create(
            'dc=bar,dc=foo',
            ['cn' => 'bar'],
        );

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar'),
        );

        $mockAccessControl = $this->createMock(AccessControlInterface::class);
        $mockAccessControl
            ->method('filterEntry')
            ->willReturnCallback(static function (TokenInterface $token, Entry $entry) use ($entry1): ?Entry {
                return $entry === $entry1 ? null : $entry;
            });

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator(
                $entry1,
                $entry2,
            )));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $subject = $this->makeHandler($mockAccessControl);
        $this->drive($subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(2, new SearchResultEntry($entry2)),
            new LdapMessageResponse(
                2,
                new SearchResultDone(0),
            ),
        ]);
    }

    public function test_it_should_skip_entry_when_filter_no_longer_matches_after_acl_stripping(): void
    {
        $entry = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo', 'secret' => 'val'],
        );
        $stripped = Entry::create(
            'dc=foo,dc=bar',
            ['cn' => 'foo'],
        );

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('secret', 'val')))->base('dc=foo,dc=bar'),
        );

        $mockAccessControl = $this->createMock(AccessControlInterface::class);
        $mockAccessControl
            ->method('filterEntry')
            ->willReturn($stripped);

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturnCallback(static fn(Entry $e): bool => $e === $entry);

        $subject = $this->makeHandler($mockAccessControl);
        $this->drive($subject, $search);

        $this->assertSentMessages([
            new LdapMessageResponse(
                2,
                new SearchResultDone(0),
            ),
        ]);
    }

    public function test_abandon_mid_stream_stops_entries_and_sends_no_response(): void
    {
        $entries = array_map(
            static fn(int $i): Entry => Entry::create("cn=$i,dc=foo,dc=bar"),
            range(1, 51),
        );

        $abandonSignal = new LdapMessageRequest(3, new AbandonRequest(2));

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator(...$entries)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->mockQueue
            ->method('peekForCancelSignal')
            ->willReturn($abandonSignal);

        $this->drive($this->subject, $search);

        $sentDone = array_filter(
            $this->sentMessages,
            static fn(LdapMessageResponse $r): bool => $r->getResponse() instanceof SearchResultDone,
        );

        self::assertEmpty($sentDone);
    }

    public function test_cancel_mid_stream_stops_entries_and_sends_canceled_plus_success(): void
    {
        $entries = array_map(
            static fn(int $i): Entry => Entry::create("cn=$i,dc=foo,dc=bar"),
            range(1, 51),
        );

        $cancelSignal = new LdapMessageRequest(3, new CancelRequest(2));

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator(...$entries)));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->mockQueue
            ->method('peekForCancelSignal')
            ->willReturn($cancelSignal);

        $this->drive($this->subject, $search);

        $nonEntryMessages = array_values(array_filter(
            $this->sentMessages,
            static fn(LdapMessageResponse $r): bool => !$r->getResponse() instanceof SearchResultEntry,
        ));

        self::assertEquals(
            [
                new LdapMessageResponse(
                    2,
                    new SearchResultDone(ResultCode::CANCELED),
                ),
                new LdapMessageResponse(
                    3,
                    new ExtendedResponse(new LdapResult(ResultCode::SUCCESS)),
                ),
            ],
            $nonEntryMessages,
        );
    }

    public function test_non_critical_unsupported_control_does_not_cause_an_error(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
            new Control('1.2.3.4.5', criticality: false),
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $search,
        );

        $this->assertSentMessages([
            new LdapMessageResponse(
                2,
                new SearchResultDone(ResultCode::SUCCESS),
            ),
        ]);
    }

    public function test_sort_control_appends_sorting_response_control_to_done_message(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
            new SortingControl(SortKey::ascending('cn')),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $search,
        );

        $done = end($this->sentMessages);
        self::assertInstanceOf(LdapMessageResponse::class, $done);
        $sortControl = $done->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortControl,
        );
        self::assertSame(
            0,
            $sortControl->getResult(),
        );
    }

    public function test_sort_by_unknown_attribute_reports_no_such_attribute(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
            new SortingControl(SortKey::ascending('bogusAttr')),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $search,
        );

        $done = end($this->sentMessages);
        self::assertInstanceOf(LdapMessageResponse::class, $done);
        $sortControl = $done->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortControl,
        );
        self::assertSame(
            ResultCode::NO_SUCH_ATTRIBUTE,
            $sortControl->getResult(),
        );
        self::assertSame(
            'bogusAttr',
            $sortControl->getAttribute(),
        );
    }

    public function test_sort_by_attribute_without_ordering_rule_reports_inappropriate_matching(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
            new SortingControl(SortKey::ascending('userPassword')),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $search,
        );

        $done = end($this->sentMessages);
        self::assertInstanceOf(LdapMessageResponse::class, $done);
        $sortControl = $done->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortControl,
        );
        self::assertSame(
            ResultCode::INAPPROPRIATE_MATCHING,
            $sortControl->getResult(),
        );
    }

    public function test_a_repeated_sort_key_attribute_reports_unwilling_to_perform(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
            new SortingControl(
                SortKey::ascending('cn'),
                SortKey::descending('CN'),
            ),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $search,
        );

        $done = end($this->sentMessages);
        self::assertInstanceOf(LdapMessageResponse::class, $done);
        $sortControl = $done->controls()->get(Control::OID_SORTING_RESPONSE);
        self::assertInstanceOf(
            SortingResponseControl::class,
            $sortControl,
        );
        self::assertSame(
            ResultCode::UNWILLING_TO_PERFORM,
            $sortControl->getResult(),
        );
    }

    public function test_an_unsortable_critical_sort_fails_the_search_and_returns_no_entries(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
            (new SortingControl(SortKey::ascending('bogusAttr')))->setCriticality(true),
        );

        $this->mockBackend
            ->expects(self::never())
            ->method('search');

        $this->drive(
            $this->subject,
            $search,
        );

        self::assertCount(
            1,
            $this->sentMessages,
            'No entries may be returned when a critical sort cannot be honored.',
        );

        $done = end($this->sentMessages);
        self::assertInstanceOf(LdapMessageResponse::class, $done);
        $response = $done->getResponse();
        self::assertInstanceOf(
            SearchResultDone::class,
            $response,
        );
        self::assertSame(
            ResultCode::UNAVAILABLE_CRITICAL_EXTENSION,
            $response->getResultCode(),
        );
        self::assertInstanceOf(
            SortingResponseControl::class,
            $done->controls()->get(Control::OID_SORTING_RESPONSE),
        );
    }

    public function test_an_unsortable_non_critical_sort_still_returns_entries(): void
    {
        $entry = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
            new SortingControl(SortKey::ascending('bogusAttr')),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator($entry)));
        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->drive(
            $this->subject,
            $search,
        );

        self::assertCount(
            2,
            $this->sentMessages,
        );
    }

    public function test_no_sort_control_does_not_append_sorting_response_control(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::present('cn')))->base('dc=foo,dc=bar'),
        );

        $this->mockBackend
            ->method('search')
            ->willReturn(new EntryStream($this->makeGenerator()));

        $this->drive(
            $this->subject,
            $search,
        );

        $done = end($this->sentMessages);
        self::assertInstanceOf(LdapMessageResponse::class, $done);
        self::assertNull($done->controls()->get(Control::OID_SORTING_RESPONSE));
    }

    private static function searchRequest(): SearchRequest
    {
        return (new SearchRequest(Filters::equal('foo', 'bar')))
            ->base('dc=foo,dc=bar');
    }

    private function makeHandler(
        AccessControlInterface $accessControl,
        ?SearchLimits $limits = null,
    ): ServerSearchHandler {
        return new ServerSearchHandler(
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
            accessControl: $accessControl,
            schema: $this->schema,
            limits: $limits ?? new SearchLimits(),
        );
    }

    /**
     * Drives the handler's stream through the writer so it flushes and polls for cancellation.
     */
    private function drive(
        ServerSearchHandler $subject,
        LdapMessageRequest $search,
    ): OperationResult {
        $stream = $subject->handleRequest(
            $search,
            $this->mockToken,
        );

        return (new ResponseWriter($this->mockQueue))->write(
            $stream,
            $search->getMessageId(),
        );
    }

    private function makeGenerator(Entry ...$entries): Generator
    {
        yield from $entries;
    }

    /**
     * @param list<LdapMessageResponse> $expected
     */
    private function assertSentMessages(array $expected): void
    {
        self::assertEquals(
            $expected,
            $this->sentMessages,
        );
    }
}
