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
use FreeDSx\Ldap\Entry\Entries;
use FreeDSx\Ldap\Entry\Entry;
use FreeDSx\Ldap\Exception\OperationException;
use FreeDSx\Ldap\LdapClient;
use FreeDSx\Ldap\Operation\Request\SearchRequest;
use FreeDSx\Ldap\Server\RequestContext;
use FreeDSx\Ldap\Server\RequestHandler\ProxyHandler;
use FreeDSx\Ldap\Server\Token\BindToken;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

final class ProxyHandlerTest extends TestCase
{
    private ProxyHandler $subject;

    private LdapClient&MockObject $mockClient;

    private RequestContext&MockObject $mockContext;

    protected function setUp(): void
    {
        $this->mockClient = $this->createMock(LdapClient::class);
        $this->mockContext = $this->createMock(RequestContext::class);

        $this->mockContext
            ->method('controls')
            ->willReturn(new ControlBag());
        $this->mockContext
            ->method('token')
            ->willReturn(new BindToken('foo', 'bar'));

        $this->subject = new ProxyHandler($this->mockClient);;
    }

    public function test_it_should_handle_a_root_dse_request(): void
    {
        $rootDse = new Entry('');

        $this->mockClient
            ->expects(self::once())
            ->method('search')
            ->willReturn(new Entries($rootDse));

        self::assertSame(
            $rootDse,
            $this->subject->rootDse(
                $this->mockContext,
                $this->createMock(SearchRequest::class),
                new Entry('')
            )
        );
    }

    public function test_it_should_handle_a_root_dse_request_when_non_is_returned(): void
    {
        self::expectException(OperationException::class);
        self::expectExceptionMessage('Entry not found.');

        $this->mockClient
            ->method('search')
            ->willReturn(new Entries());

        $this->subject->rootDse(
            $this->mockContext,
            $this->createMock(SearchRequest::class),
            new Entry('')
        );
    }
}
