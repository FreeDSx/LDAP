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

namespace Tests\Unit\FreeDSx\Ldap\Server;

use FreeDSx\Ldap\Exception\ProtocolException;
use FreeDSx\Ldap\Server\Paging\PagingRequests;
use FreeDSx\Ldap\Server\RequestHistory;
use PHPUnit\Framework\TestCase;

final class RequestHistoryTest extends TestCase
{
    private RequestHistory $subject;

    protected function setUp(): void
    {
        $this->subject = new RequestHistory();
    }

    public function test_it_should_add_a_valid_id(): void
    {
        $this->subject->addId(1);

        self::assertSame(
            [1],
            $this->subject->getIds()
        );
    }

    public function test_it_should_throw_when_adding_an_existing_id(): void
    {
        self::expectException(ProtocolException::class);

        $this->subject->addId(1);
        $this->subject->addId(1);
    }

    public function test_it_should_throw_when_adding_an_invalid_id(): void
    {
        self::expectException(ProtocolException::class);

        $this->subject->addId(0);
    }

    public function test_it_should_get_the_paging_requests(): void
    {

        self::assertFalse(
            $this->subject->pagingRequest()->has('foo')
        );
    }
}
