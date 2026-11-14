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

namespace Tests\Unit\FreeDSx\Ldap\Server\Paging;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Operation\ResultCode;
use FreeDSx\Ldap\Operations;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Logging\EventContext;
use FreeDSx\Ldap\Server\Logging\EventLogger;
use FreeDSx\Ldap\Server\Logging\EventLogPolicy;
use FreeDSx\Ldap\Server\Logging\ServerEvent;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\Paging\PagingRequestFingerprint;
use FreeDSx\Ldap\Server\Paging\PagingSession;
use FreeDSx\Ldap\Server\Paging\PagingSessions;
use FreeDSx\Ldap\Server\Paging\PagingSessionTracker;
use PHPUnit\Framework\TestCase;
use Tests\Support\FreeDSx\Ldap\Logging\RecordingLogger;

final class PagingSessionTrackerTest extends TestCase
{
    private const MAX_SESSIONS = 2;

    private PagingSessions $sessions;

    private RecordingLogger $logger;

    private PagingSessionTracker $subject;

    protected function setUp(): void
    {
        $this->sessions = new PagingSessions();
        $this->logger = new RecordingLogger();
        $this->subject = new PagingSessionTracker(
            $this->sessions,
            self::MAX_SESSIONS,
            new EventLogger(
                $this->logger,
                EventLogPolicy::default(),
            ),
        );
    }

    public function test_a_search_that_is_just_starting_resumes_no_session(): void
    {
        self::assertNull($this->subject->find(self::pagingRequest()));
    }

    public function test_a_continuation_resumes_the_session_its_cookie_names(): void
    {
        $session = self::sessionFor(
            self::pagingRequest(),
            'cookie',
        );
        $this->sessions->add($session);

        self::assertSame(
            $session,
            $this->subject->find(self::pagingRequest('cookie')),
        );
    }

    public function test_a_continuation_naming_no_session_is_unwilling_to_perform(): void
    {
        try {
            $this->subject->find(self::pagingRequest('unknown'));
            self::fail('The continuation should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::UNWILLING_TO_PERFORM,
                $e->getCode(),
            );
        }
    }

    public function test_a_continuation_of_the_same_search_is_accepted(): void
    {
        $this->expectNotToPerformAssertions();

        $this->subject->assertSameSearch(
            self::pagingRequest('cookie'),
            self::sessionFor(
                self::pagingRequest(),
                'cookie',
            ),
        );
    }

    public function test_a_continuation_of_another_search_is_an_operations_error(): void
    {
        try {
            $this->subject->assertSameSearch(
                self::pagingRequest(
                    'cookie',
                    '(cn=other)',
                ),
                self::sessionFor(
                    self::pagingRequest(),
                    'cookie',
                ),
            );
            self::fail('The continuation should have been refused.');
        } catch (OperationException $e) {
            self::assertSame(
                ResultCode::OPERATIONS_ERROR,
                $e->getCode(),
            );
        }
    }

    public function test_a_first_page_starts_a_session_under_the_cookie_it_returns(): void
    {
        $cookie = $this->subject->keep(
            self::pagingRequest(),
            null,
            PageCursor::afterEntry(10),
        );

        self::assertSame(
            [true, 1],
            [$this->sessions->has($cookie), $this->sessions->count()],
        );
    }

    public function test_a_later_page_advances_its_session_under_a_new_cookie(): void
    {
        $session = self::sessionFor(
            self::pagingRequest(),
            'cookie',
        );
        $this->sessions->add($session);

        $cookie = $this->subject->keep(
            self::pagingRequest('cookie'),
            $session,
            PageCursor::afterEntry(20),
        );

        self::assertSame(
            [$cookie, 1],
            [$session->nextCookie(), $this->sessions->count()],
        );
        self::assertNotSame(
            'cookie',
            $cookie,
        );
    }

    public function test_a_new_session_at_the_limit_evicts_the_oldest_and_records_it(): void
    {
        $oldest = self::sessionFor(
            self::pagingRequest(),
            'oldest',
        );
        $this->sessions->add($oldest);
        $this->sessions->add(self::sessionFor(
            self::pagingRequest(),
            'newer',
        ));

        $this->subject->keep(
            self::pagingRequest(),
            null,
            PageCursor::afterEntry(10),
        );

        self::assertSame(
            [false, self::MAX_SESSIONS],
            [$this->sessions->has('oldest'), $this->sessions->count()],
        );
        self::assertSame(
            [[ServerEvent::PagingSessionEvicted->value, self::MAX_SESSIONS]],
            array_map(
                static fn(array $record): array => [
                    $record['context'][EventContext::EVENT] ?? null,
                    $record['context'][EventContext::LIMIT] ?? null,
                ],
                $this->logger->records,
            ),
        );
    }

    public function test_an_ended_session_can_no_longer_be_resumed(): void
    {
        $session = self::sessionFor(
            self::pagingRequest(),
            'cookie',
        );
        $this->sessions->add($session);

        $this->subject->end($session);

        self::assertFalse($this->sessions->has('cookie'));
    }

    private static function pagingRequest(
        string $cookie = '',
        string $filter = '(cn=user)',
    ): PagingRequest {
        return new PagingRequest(
            new PagingControl(
                100,
                $cookie,
            ),
            self::search($filter),
            new ControlBag(),
        );
    }

    private static function search(string $filter): SearchRequest
    {
        return Operations::search(Filters::raw($filter))->base('dc=foo,dc=bar');
    }

    private static function sessionFor(
        PagingRequest $pagingRequest,
        string $cookie,
    ): PagingSession {
        return new PagingSession(
            (new PagingRequestFingerprint())->of($pagingRequest),
            $cookie,
            PageCursor::afterEntry(1),
        );
    }
}
