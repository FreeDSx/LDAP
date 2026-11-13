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

use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Paging\PagingSession;
use FreeDSx\Ldap\Server\Paging\PagingSessions;
use PHPUnit\Framework\TestCase;

final class PagingSessionsTest extends TestCase
{
    private PagingSession $session;

    private PagingSessions $subject;

    protected function setUp(): void
    {
        $this->session = $this->sessionWithCookie('bar');

        $this->subject = new PagingSessions();
        $this->subject->add($this->session);
    }

    public function test_it_should_return_true_when_it_has_the_session(): void
    {
        self::assertTrue($this->subject->has('bar'));
    }

    public function test_it_should_return_false_when_it_does_not_have_the_session(): void
    {
        self::assertFalse($this->subject->has('foo'));
    }

    public function test_it_should_return_the_session_when_it_exists(): void
    {
        self::assertSame(
            $this->session,
            $this->subject->findByNextCookie('bar'),
        );
    }

    public function test_it_should_remove_the_session(): void
    {
        $this->subject->remove($this->session);

        self::assertFalse($this->subject->has('bar'));
    }

    public function test_it_should_add_the_session(): void
    {
        $new = $this->sessionWithCookie('foo');
        $this->subject->add($new);

        self::assertSame(
            $new,
            $this->subject->findByNextCookie('foo'),
        );
    }

    public function test_it_refuses_a_session_whose_cookie_is_already_held(): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->add($this->sessionWithCookie('bar'));
    }

    public function test_it_should_throw_an_exception_when_the_session_does_not_exist(): void
    {
        $this->expectException(ProtocolException::class);

        $this->subject->findByNextCookie('ohno');
    }

    public function test_the_oldest_session_is_evicted_once_the_limit_is_reached(): void
    {
        $this->subject->add($this->sessionWithCookie('foo'));

        self::assertTrue($this->subject->evictOldestAtLimit(2));
        self::assertFalse($this->subject->has('bar'));
        self::assertTrue($this->subject->has('foo'));
    }

    public function test_no_session_is_evicted_below_the_limit(): void
    {
        self::assertFalse($this->subject->evictOldestAtLimit(2));
        self::assertTrue($this->subject->has('bar'));
    }

    public function test_no_session_is_evicted_without_a_limit(): void
    {
        self::assertFalse($this->subject->evictOldestAtLimit(0));
        self::assertTrue($this->subject->has('bar'));
    }

    private function sessionWithCookie(string $cookie): PagingSession
    {
        return new PagingSession(
            'fingerprint',
            $cookie,
            PageCursor::afterEntry(1),
        );
    }
}
