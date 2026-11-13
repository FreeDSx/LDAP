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

use FreeDSx\Ldap\Server\Backend\Storage\Paging\PageCursor;
use FreeDSx\Ldap\Server\Paging\PagingSession;
use PHPUnit\Framework\TestCase;

final class PagingSessionTest extends TestCase
{
    private PageCursor $cursor;

    private PagingSession $subject;

    protected function setUp(): void
    {
        $this->cursor = PageCursor::afterEntry(2);
        $this->subject = new PagingSession(
            'fingerprint',
            'cookie',
            $this->cursor,
        );
    }

    public function test_it_resumes_from_the_cursor_it_started_with(): void
    {
        self::assertSame(
            $this->cursor,
            $this->subject->cursor(),
        );
    }

    public function test_advancing_resumes_from_the_cursor_under_the_new_cookie(): void
    {
        $cursor = PageCursor::afterEntry(5);

        $this->subject->advance(
            'next',
            $cursor,
        );

        self::assertSame(
            'next',
            $this->subject->nextCookie(),
        );
        self::assertSame(
            $cursor,
            $this->subject->cursor(),
        );
    }

    public function test_advancing_keeps_the_fingerprint(): void
    {
        $this->subject->advance(
            'next',
            PageCursor::afterEntry(5),
        );

        self::assertSame(
            'fingerprint',
            $this->subject->fingerprint(),
        );
    }
}
