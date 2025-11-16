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

use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Server\Paging\PagingResponse;
use PHPUnit\Framework\TestCase;

final class PagingResponseTest extends TestCase
{
    private PagingResponse $subject;

    protected function setUp(): void
    {
        $this->subject = new PagingResponse(new Entries());
    }

    public function test_it_should_not_be_complete_by_default(): void
    {
        self::assertFalse($this->subject->isComplete());
    }

    public function test_it_should_have_the_size_remaining(): void
    {
        self::assertSame(
            0,
            $this->subject->getRemaining(),
        );
    }

    public function test_it_should_get_the_entries(): void
    {
        self::assertEquals(
            new Entries(),
            $this->subject->getEntries(),
        );
    }

    public function test_it_should_make_a_complete_response(): void
    {
        $this->subject = PagingResponse::makeFinal(new Entries());

        self::assertTrue($this->subject->isComplete());;
    }

    public function test_it_should_make_a_regular_response(): void
    {
        $this->subject = PagingResponse::make(new Entries());

        self::assertFalse($this->subject->isComplete());
    }
}
