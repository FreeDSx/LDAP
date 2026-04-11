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

use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\Response\SearchResultDone;
use FreeDSx\Ldap\Operation\Response\SearchResultEntry;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Protocol\LdapMessageRequest;
use FreeDSx\Ldap\Protocol\LdapMessageResponse;
use FreeDSx\Ldap\Protocol\Queue\ServerQueue;
use FreeDSx\Ldap\Protocol\ServerProtocolHandler\ServerSearchHandler;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\LdapBackendInterface;
use FreeDSx\Ldap\Server\Backend\SearchContext;
use FreeDSx\Ldap\Server\Backend\Storage\FilterEvaluatorInterface;
use FreeDSx\Ldap\Server\Token\TokenInterface;
use Generator;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ServerSearchHandlerTest extends TestCase
{
    private ServerSearchHandler $subject;

    private ServerQueue&MockObject $mockQueue;

    private LdapBackendInterface&MockObject $mockBackend;

    private FilterEvaluatorInterface&MockObject $mockFilterEvaluator;

    private TokenInterface&MockObject $mockToken;

    protected function setUp(): void
    {
        $this->mockToken = $this->createMock(TokenInterface::class);
        $this->mockQueue = $this->createMock(ServerQueue::class);
        $this->mockBackend = $this->createMock(LdapBackendInterface::class);
        $this->mockFilterEvaluator = $this->createMock(FilterEvaluatorInterface::class);

        $this->subject = new ServerSearchHandler(
            queue: $this->mockQueue,
            backend: $this->mockBackend,
            filterEvaluator: $this->mockFilterEvaluator,
        );
    }

    private function makeGenerator(Entry ...$entries): Generator
    {
        yield from $entries;
    }

    public function test_it_should_send_entries_from_the_backend_to_the_client(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar')
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->with(self::isInstanceOf(SearchContext::class))
            ->willReturn($this->makeGenerator($entry1, $entry2));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(2, new SearchResultEntry($entry1)),
                new LdapMessageResponse(2, new SearchResultEntry($entry2)),
                new LdapMessageResponse(
                    2,
                    new SearchResultDone(0, 'dc=foo,dc=bar')
                ),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_filter_entries_that_do_not_match_the_filter(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar')
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn($this->makeGenerator($entry1, $entry2));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturnOnConsecutiveCalls(true, false);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(2, new SearchResultEntry($entry1)),
                new LdapMessageResponse(
                    2,
                    new SearchResultDone(0, 'dc=foo,dc=bar')
                ),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }

    public function test_it_should_send_a_SearchResultDone_with_an_operation_exception_thrown_from_the_backend(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal(
                'foo',
                'bar'
            )))->base('dc=foo,dc=bar')
        );

        $this->mockBackend
            ->method('search')
            ->willThrowException(
                new OperationException(
                    "Fail",
                    ResultCode::OPERATIONS_ERROR
                ),
            );

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(self::equalTo(new LdapMessageResponse(
                2,
                new SearchResultDone(
                    ResultCode::OPERATIONS_ERROR,
                    'dc=foo,dc=bar',
                    "Fail"
                )
            )));

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
                ->sizeLimit(1)
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn($this->makeGenerator($entry1, $entry2));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(2, new SearchResultEntry($entry1)),
                new LdapMessageResponse(
                    2,
                    new SearchResultDone(ResultCode::SIZE_LIMIT_EXCEEDED, 'dc=foo,dc=bar')
                ),
            );

        $this->subject->handleRequest($search, $this->mockToken);
    }

    public function test_it_should_not_enforce_size_limit_when_zero(): void
    {
        $entry1 = Entry::create('dc=foo,dc=bar', ['cn' => 'foo']);
        $entry2 = Entry::create('dc=bar,dc=foo', ['cn' => 'bar']);

        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))
                ->base('dc=foo,dc=bar')
                ->sizeLimit(0)
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn($this->makeGenerator($entry1, $entry2));

        $this->mockFilterEvaluator
            ->method('evaluate')
            ->willReturn(true);

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(2, new SearchResultEntry($entry1)),
                new LdapMessageResponse(2, new SearchResultEntry($entry2)),
                new LdapMessageResponse(2, new SearchResultDone(0, 'dc=foo,dc=bar')),
            );

        $this->subject->handleRequest($search, $this->mockToken);
    }

    public function test_it_should_send_a_successful_SearchResultDone_when_no_entries_match(): void
    {
        $search = new LdapMessageRequest(
            2,
            (new SearchRequest(Filters::equal('foo', 'bar')))->base('dc=foo,dc=bar')
        );

        $this->mockBackend
            ->expects(self::once())
            ->method('search')
            ->willReturn($this->makeGenerator());

        $this->mockQueue
            ->expects(self::once())
            ->method('sendMessage')
            ->with(
                new LdapMessageResponse(
                    2,
                    new SearchResultDone(0, 'dc=foo,dc=bar')
                ),
            );

        $this->subject->handleRequest(
            $search,
            $this->mockToken,
        );
    }
}
