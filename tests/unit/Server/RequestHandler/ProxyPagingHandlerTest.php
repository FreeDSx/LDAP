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

namespace Tests\Unit\FreeDSx\Ldap\Server\RequestHandler;

use FreeDSx\Ldap\Control\ControlBag;
use FreeDSx\Ldap\Control\PagingControl;
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Search\Filters;
use FreeDSx\Ldap\Search\Paging;
use FreeDSx\Ldap\Server\Paging\PagingRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\ProxyPagingHandler;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyPagingHandlerTest extends TestCase
{
    private ProxyPagingHandler $subject;

    private LdapClient&MockObject $mockClient;

    private RequestContext&MockObject $mockContext;

    protected function setUp(): void
    {
        $this->mockContext = $this->createMock(RequestContext::class);
        $this->mockClient = $this->createMock(LdapClient::class);

        $this->mockContext
            ->method('controls')
            ->willReturn(new ControlBag());

        $this->subject = new ProxyPagingHandler($this->mockClient);
    }

    public function test_it_should_handle_a_paging_request_when_paging_is_still_going(): void
    {
        $paging = $this->createMock(Paging::class);

        $request = new SearchRequest(Filters::equal('cn', 'foo'));
        $entries = new Entries(new Entry('cn=foo,dc=foo,dc=bar'));

        $this->mockClient
            ->expects($this->once())
            ->method('paging')
            ->willReturn($paging);

        $paging->method('isCritical')
            ->willReturn($paging);
        $paging->method('getEntries')
            ->with(25)
            ->willReturn($entries);
        $paging->method('hasEntries')
            ->willReturn(true);
        $paging->method('sizeEstimate')
            ->willReturn(25);

        $pagingRequest = new PagingRequest(
            new PagingControl(25, ''),
            $request,
            new ControlBag(),
            'foo'
        );

        self::assertFalse(
            $this->subject->page($pagingRequest, $this->mockContext)->isComplete(),
        );
        self::assertEquals(
            $entries,
            $this->subject->page($pagingRequest, $this->mockContext)->getEntries(),
        );
        self::assertSame(
            25,
            $this->subject->page($pagingRequest, $this->mockContext)->getRemaining(),
        );
    }

    public function test_it_should_handle_a_paging_request_when_paging_is_complete(): void
    {
        $paging = $this->createMock(Paging::class);

        $request = new SearchRequest(Filters::equal('cn', 'foo'));
        $entries = new Entries(new Entry('cn=foo,dc=foo,dc=bar'));

        $this->mockClient
            ->expects($this->once())
            ->method('paging')
            ->willReturn($paging);

        $paging->method('isCritical')
            ->willReturn($paging);
        $paging->method('getEntries')
            ->with(25)
            ->willReturn($entries);
        $paging->method('hasEntries')
            ->willReturn(false);

        $pagingRequest = new PagingRequest(
            new PagingControl(25, ''),
            $request,
            new ControlBag(),
            'foo'
        );

        self::assertTrue($this->subject->page($pagingRequest, $this->mockContext)->isComplete());
        self::assertEquals(
            $entries,
            $this->subject->page($pagingRequest, $this->mockContext)->getEntries(),
        );
        self::assertSame(
            0,
            $this->subject->page($pagingRequest, $this->mockContext)->getRemaining(),
        );
    }
}
